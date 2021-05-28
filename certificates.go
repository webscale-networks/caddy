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

package caddy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
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

// CacheUnmanagedTLSCertificate adds tlsCert to the certificate cache.
// It staples OCSP if possible.
//
// This method is safe for concurrent use.
func (cfg *Config) CacheUnmanagedTLSCertificate(tlsCert tls.Certificate, tags []string) error {
	var cert Certificate
	err := fillCertFromLeaf(&cert, tlsCert)
	if err != nil {
		return err
	}
	cert.CertMetadata.Tags = tags
	cfg.certCache.cacheCertificate(cert)
	return nil
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

// makeCertificate turns a certificate PEM bundle and a key PEM block into
// a Certificate with necessary metadata from parsing its bytes filled into
// its struct fields for convenience (except for the OnDemand and Managed
// flags; it is up to the caller to set those properties!). This function
// does NOT staple OCSP.
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

// HostQualifies returns true if the hostname alone
// appears eligible for automagic TLS. For example:
// localhost, empty hostname, and IP addresses are
// not eligible because we cannot obtain certificates
// for those names. Wildcard names are allowed, as long
// as they conform to CABF requirements (only one wildcard
// label, and it must be the left-most label). Names with
// certain special characters that are commonly accidental
// are also rejected.
func HostQualifies(hostname string) bool {
	return hostname != "localhost" && // localhost is ineligible

		// hostname must not be empty
		strings.TrimSpace(hostname) != "" &&

		// only one wildcard label allowed, and it must be left-most
		(!strings.Contains(hostname, "*") ||
			(strings.Count(hostname, "*") == 1 &&
				strings.HasPrefix(hostname, "*."))) &&

		// must not start or end with a dot
		!strings.HasPrefix(hostname, ".") &&
		!strings.HasSuffix(hostname, ".") &&

		// must not contain other common special characters
		!strings.ContainsAny(hostname, "()[]{}<>\\/!@#$%^&|:;+='\"") &&

		// cannot be an IP address, see
		// https://community.letsencrypt.org/t/certificate-for-static-ip/84/2?u=mholt
		net.ParseIP(hostname) == nil
}
