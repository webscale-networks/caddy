// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Certificate is a tls.Certificate with associated metadata tacked on.
// Even if the metadata can be obtained by parsing the certificate,
// we are more efficient by extracting the metadata onto this struct,
// but at the cost of slightly higher memory use.
type Certificate struct {
	tls.Certificate

	// Names is the list of names this certificate is written for.
	// The first is the CommonName (if any), the rest are SAN.
	Names []string

	// NotAfter is when the certificate expires.
	NotAfter time.Time

	// OCSP contains the certificate's parsed OCSP response.
	ocsp *ocsp.Response

	// The hex-encoded hash of this cert's chain's bytes.
	hash string

	// Whether this certificate is under our management
	managed bool

	// These fields are extracted to here mainly for custom
	// selection logic, which is optional; callers may wish
	// to use this information to choose a certificate when
	// more than one match the ClientHello
	CertMetadata
}

// CertMetadata is data extracted from a parsed x509
// certificate which is purely optional but can be
// useful when selecting which certificate to use
// if multiple match a ClientHello's ServerName.
// The more fields we add to this struct, the more
// memory use will increase at scale with large
// numbers of certificates in the cache.
type CertMetadata struct {
	Tags               []string // user-provided and arbitrary
	Subject            pkix.Name
	SerialNumber       *big.Int
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
}

// HasTag returns true if cm.Tags has tag.
func (cm CertMetadata) HasTag(tag string) bool {
	for _, t := range cm.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// CacheUnmanagedCertificatePEMBytes makes a certificate out of the PEM bytes
// of the certificate and key, then caches it in memory.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedCertificatePEMBytes(certBytes, keyBytes []byte, tags []string) error {
	cert, err := makeCertificate(certBytes, keyBytes)
	if err != nil {
		return err
	}
	cert.CertMetadata.Tags = tags
	cfg.certCache.cacheCertificate(cert)
	return nil
}

// CacheUnmanagedCertificatePEMFile loads a certificate for host using certFile
// and keyFile, which must be in PEM format. It stores the certificate in
// the in-memory cache.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedCertificatePEMFile(certFile, keyFile string, tags []string) error {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}
	cert, err := makeCertificate(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}
	cert.CertMetadata.Tags = tags
	cfg.certCache.cacheCertificate(cert)
	return nil
}

// ParseCertificate parses the given *.pem file into certificate and key bytes.
// Any errors are returned.
// This implementation was moved from caddytls/setup.go to make it available to
// multiple packages and avoid duplicate code.
func ParseCertificate(file string) ([]byte, []byte, error) {
	certBuilder, keyBuilder := new(bytes.Buffer), new(bytes.Buffer)
	var foundKey bool // use only the first key in the file

	bundle, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}

	for {
		// Decode next block so we can see what type it is
		var derBlock *pem.Block
		derBlock, bundle = pem.Decode(bundle)
		if derBlock == nil {
			break
		}

		if derBlock.Type == "CERTIFICATE" {
			// Re-encode certificate as PEM, appending to certificate chain
			if err := pem.Encode(certBuilder, derBlock); err != nil {
				log.Println("[ERROR] failed to write PEM encoding: ", err)
			}
		} else if derBlock.Type == "EC PARAMETERS" {
			// EC keys generated from openssl can be composed of two blocks:
			// parameters and key (parameter block should come first)
			if !foundKey {
				// Encode parameters
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					log.Println("[ERROR] failed to write PEM encoding: ", err)
				}

				// Key must immediately follow
				derBlock, bundle = pem.Decode(bundle)
				if derBlock == nil || derBlock.Type != "EC PRIVATE KEY" {
					return nil, nil, fmt.Errorf("%s: expected elliptic private key to immediately follow EC parameters", file)
				}
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					log.Println("[ERROR] failed to write PEM encoding: ", err)
				}
				foundKey = true
			}
		} else if derBlock.Type == "PRIVATE KEY" || strings.HasSuffix(derBlock.Type, " PRIVATE KEY") {
			// RSA key
			if !foundKey {
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					log.Println("[ERROR] failed to write PEM encoding: ", err)
				}
				foundKey = true
			}
		} else {
			return nil, nil, fmt.Errorf("%s: unrecognized PEM block type: %s", file, derBlock.Type)
		}
	}

	certPEMBytes, keyPEMBytes := certBuilder.Bytes(), keyBuilder.Bytes()
	if len(certPEMBytes) == 0 {
		return nil, nil, fmt.Errorf("%s: failed to parse PEM data", file)
	}
	if len(keyPEMBytes) == 0 {
		return nil, nil, fmt.Errorf("%s: no private key block found", file)
	}
	return certPEMBytes, keyPEMBytes, nil
}

// makeCertificate turns a certificate PEM bundle and a key PEM block into
// a Certificate with necessary metadata from parsing its bytes filled into
// its struct fields for convenience.
func makeCertificate(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	var cert Certificate

	// Convert to a tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return cert, err
	}

	// Extract necessary metadata
	err = fillCertFromLeaf(&cert, tlsCert)
	if err != nil {
		return cert, err
	}

	return cert, nil
}

// fillCertFromLeaf populates metadata fields on cert from tlsCert.
func fillCertFromLeaf(cert *Certificate, tlsCert tls.Certificate) error {
	if len(tlsCert.Certificate) == 0 {
		return fmt.Errorf("certificate is empty")
	}
	cert.Certificate = tlsCert

	// the leaf cert should be the one for the site; it has what we need
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return err
	}

	if leaf.Subject.CommonName != "" { // TODO: CommonName is deprecated
		cert.Names = []string{strings.ToLower(leaf.Subject.CommonName)}
	}
	for _, name := range leaf.DNSNames {
		if name != leaf.Subject.CommonName { // TODO: CommonName is deprecated
			cert.Names = append(cert.Names, strings.ToLower(name))
		}
	}
	for _, ip := range leaf.IPAddresses {
		if ipStr := ip.String(); ipStr != leaf.Subject.CommonName { // TODO: CommonName is deprecated
			cert.Names = append(cert.Names, strings.ToLower(ipStr))
		}
	}
	for _, email := range leaf.EmailAddresses {
		if email != leaf.Subject.CommonName { // TODO: CommonName is deprecated
			cert.Names = append(cert.Names, strings.ToLower(email))
		}
	}
	if len(cert.Names) == 0 {
		return fmt.Errorf("certificate has no names")
	}

	// save the hash of this certificate (chain) and
	// expiration date, for necessity and efficiency
	cert.hash = hashCertificateChain(cert.Certificate.Certificate)
	cert.NotAfter = leaf.NotAfter

	// these other fields are strictly optional to
	// store in their decoded forms, but they are
	// here for convenience in case the caller wishes
	// to select certificates using custom logic when
	// more than one may complete a handshake
	cert.Subject = leaf.Subject
	cert.SerialNumber = leaf.SerialNumber
	cert.PublicKeyAlgorithm = leaf.PublicKeyAlgorithm

	return nil
}

// hashCertificateChain computes the unique hash of certChain,
// which is the chain of DER-encoded bytes. It returns the
// hex encoding of the hash.
func hashCertificateChain(certChain [][]byte) string {
	h := sha256.New()
	for _, certInChain := range certChain {
		h.Write(certInChain)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
