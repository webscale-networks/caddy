package tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/mholt/certmagic"
)

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
//
// This implementation is based on certmagic's 'makeCertificate' function but
// ported here for use by Webscale's certificate cache.
func makeCertificate(certPEMBlock, keyPEMBlock []byte) (certmagic.Certificate, error) {
	var cert certmagic.Certificate

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
// This function originally stored a hash of the certificate chain in the given
// certmagic.Certificate object. However, this field is not exported from the
// certmagic package so it is unavailable to us here. This hash is only used
// if certmagic's certificate cache is used.
func fillCertFromLeaf(cert *certmagic.Certificate, tlsCert tls.Certificate) error {
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
