// Copyright 2021 Webscale

package tls

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"
)

// Unique type for strings destined to be Caddy instance keys.
type instanceKey string

// The override cache instance key.
const OverrideCacheKey instanceKey = "strict-tls"

// AliasKeyedCache is a certificate cache that serves certificates based solely
// on the SNI in the client hello message during TLS handshakes. As such, it
// ignores what domains are covered by the certificate it is serving, checking
// only the SNI. The alias-certificate associations are written in the
// Caddyfile's 'strict_tls' directive. If a certificate is not found based on
// the SNI, the default certificate, configured from 'strict_tls.default' is
// served.
type AliasKeyedCache struct {
	// The cache is keyed by hostname.
	cache map[string]*Certificate

	// Default certificate.
	defaultCertificate *Certificate

	// Protects the cache map.
	mu sync.RWMutex
}

// NewAliasKeyedCache creates a new alias-certificate cache.
// Only Webscale's 'strict_tls' plugin should call this function.
func NewAliasKeyedCache() *AliasKeyedCache {
	return &AliasKeyedCache{
		cache:              make(map[string]*Certificate),
		defaultCertificate: nil,
	}
}

// Load adds new alias-certificate associations for the given *.pem file and the
// given list of aliases. Each alias will be associated to the given
// certificate. If the given file is not a valid PEM file, an error is returned.
// Only Webscale's 'strict_tls' plugin should call this function.
func (cache *AliasKeyedCache) Load(file string, aliases []string) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	certPEMBytes, keyPEMBytes, err := ParseCertificate(file)
	if err != nil {
		return err
	}

	cert, err := makeCertificate(certPEMBytes, keyPEMBytes)
	if err != nil {
		return err
	}

	for _, alias := range aliases {
		name := NormalizedName(alias)
		cache.cache[name] = &cert
	}
	return nil
}

// SetDefaultCertificate sets the default certificate to serve when a
// certificate cannot be found for the SNI in the client's hello message during
// TLS handshake. Only Webscale's 'strict_tls' plugin should call this function.
func (cache *AliasKeyedCache) SetDefaultCertificate(file string) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	certPEMBytes, keyPEMBytes, err := ParseCertificate(file)
	if err != nil {
		return err
	}

	cert, err := makeCertificate(certPEMBytes, keyPEMBytes)
	if err != nil {
		return err
	}
	cache.defaultCertificate = &cert
	return nil
}

// getCertificate retrieves a certificate based on the SNI in the client hello
// message. If no certificate can be found, the default certificate is served.
// If the chosen certificate is expired, an error is returned.
func (cache *AliasKeyedCache) getCertificate(hello *tls.ClientHelloInfo) (*Certificate, error) {
	name := NormalizedName(hello.ServerName)
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	cert, ok := cache.cache[name]
	if !ok {
		// The cache does not contain a certificate for the given SNI. Return
		// the default certificate that was configured.
		cert = cache.defaultCertificate
	}

	// Check expiration.
	now := time.Now()
	if now.Before(cert.NotAfter) {
		return cert, nil
	}
	return nil, fmt.Errorf("No unexpired certificate applies to %s", name)
}
