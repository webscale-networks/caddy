// Copyright 2021 Webscale

package tls

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mholt/certmagic"
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
	cache map[string]*certmagic.Certificate

	// Default certificate.
	defaultCertificate *certmagic.Certificate

	// Protects the cache map.
	mu sync.RWMutex
}

// NewAliasKeyedCache creates a new alias-certificate cache.
// Only Webscale's 'strict_tls' plugin should call this function.
func NewAliasKeyedCache() *AliasKeyedCache {
	return &AliasKeyedCache{
		cache:              make(map[string]*certmagic.Certificate),
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
		name := normalizedName(alias)
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
func (cache *AliasKeyedCache) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := normalizedName(hello.ServerName)
	// Check expiration for the selected certificate.
	now := time.Now()

	// If an unexpired certificate has been associated to this alias was found,
	// return it.
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	cert, ok := cache.cache[name]
	if ok && now.Before(cert.NotAfter) {
		return &cert.Certificate, nil
	}

	// No unexpired certificate was found, so try the default certificate.
	if now.Before(cache.defaultCertificate.NotAfter) {
		return &cache.defaultCertificate.Certificate, nil
	}

	// Out of luck. Error.
	return nil, fmt.Errorf("No unexpired certificate applies to %s", name)
}

func normalizedName(serverName string) string {
	return strings.ToLower(strings.TrimSpace(serverName))
}
