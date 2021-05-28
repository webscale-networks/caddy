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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
	"github.com/klauspost/cpuid"
)

// Config configures a certificate manager instance.
// An empty Config is not valid: use New() to obtain
// a valid Config.
type Config struct {
	// DefaultServerName specifies a server name
	// to use when choosing a certificate if the
	// ClientHello's ServerName field is empty
	DefaultServerName string

	// CertSelection chooses one of the certificates
	// with which the ClientHello will be completed.
	// If not set, the first matching certificate
	// will be used.
	CertSelection CertificateSelector

	// TrustedRoots specifies a pool of root CA
	// certificates to trust when communicating
	// over a network to a peer.
	TrustedRoots *x509.CertPool

	// Pointer to the in-memory certificate cache
	certCache *Cache
}

var Default = Config{}

// NewDefault makes a valid config based on the package
// Default config. Most users will call this function
// instead of New() since most use cases require only a
// single config for any and all certificates.
//
// If your requirements are more advanced (for example,
// multiple configs depending on the certificate), then use
// New() instead. (You will need to make your own Cache
// first.) If you only need a single Config to manage your
// certs (even if that config changes, as long as it is the
// only one), customize the Default package variable before
// calling NewDefault().
//
// All calls to NewDefault() will return configs that use the
// same, default certificate cache. All configs returned
// by NewDefault() are based on the values of the fields of
// Default at the time it is called.
func NewDefault() *Config {
	defaultCacheMu.Lock()
	if defaultCache == nil {
		defaultCache = NewCache(CacheOptions{
			// the cache will likely need to renew certificates,
			// so it will need to know how to do that, which
			// depends on the certificate being managed and which
			// can change during the lifetime of the cache; this
			// callback makes it possible to get the latest and
			// correct config with which to manage the cert,
			// but if the user does not provide one, we can only
			// assume that we are to use the default config
			GetConfigForCert: func(Certificate) (Config, error) {
				return Default, nil
			},
		})
	}
	certCache := defaultCache
	defaultCacheMu.Unlock()

	return newWithCache(certCache, Default)
}

// New makes a new, valid config based on cfg and
// uses the provided certificate cache. certCache
// MUST NOT be nil or this function will panic.
//
// Use this method when you have an advanced use case
// that requires a custom certificate cache and config
// that may differ from the Default. For example, if
// not all certificates are managed/renewed the same
// way, you need to make your own Cache value with a
// GetConfigForCert callback that returns the correct
// configuration for each certificate. However, for
// the vast majority of cases, there will be only a
// single Config, thus the default cache (which always
// uses the default Config) and default config will
// suffice, and you should use New() instead.
func New(certCache *Cache, cfg Config) *Config {
	if certCache == nil {
		panic("a certificate cache is required")
	}
	if certCache.options.GetConfigForCert == nil {
		panic("cache must have GetConfigForCert set in its options")
	}
	return newWithCache(certCache, cfg)
}

// newWithCache ensures that cfg is a valid config by populating
// zero-value fields from the Default Config. If certCache is
// nil, this function panics.
func newWithCache(certCache *Cache, cfg Config) *Config {
	if certCache == nil {
		panic("cannot make a valid config without a pointer to a certificate cache")
	}

	// fill in default values
	if cfg.DefaultServerName == "" {
		cfg.DefaultServerName = Default.DefaultServerName
	}

	// ensure the unexported fields are valid
	cfg.certCache = certCache

	return &cfg
}

// TLSConfig is an opinionated method that returns a
// recommended, modern TLS configuration that can be
// used to configure TLS listeners, which also supports
// the TLS-ALPN challenge and serves up certificates
// managed by cfg.
//
// Unlike the package TLS() function, this method does
// not, by itself, enable certificate management for
// any domain names.
//
// Feel free to further customize the returned tls.Config,
// but do not mess with the GetCertificate or NextProtos
// fields unless you know what you're doing, as they're
// necessary to solve the TLS-ALPN challenge.
func (cfg *Config) TLSConfig() *tls.Config {
	return &tls.Config{
		// these two fields necessary for TLS-ALPN challenge
		GetCertificate: cfg.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", tlsalpn01.ACMETLS1Protocol},

		// the rest recommended for modern TLS servers
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites:             preferredDefaultCipherSuites(),
		PreferServerCipherSuites: true,
	}
}

// storageHasCertResources returns true if the storage
// associated with cfg's certificate cache has all the
// resources related to the certificate for domain: the
// certificate, the private key, and the metadata.
func (cfg *Config) storageHasCertResources(domain string) bool {
	return true
}

// GetCertificate gets a certificate to satisfy clientHello. In getting
// the certificate, it abides the rules and settings defined in the
// Config that matches clientHello.ServerName. It first checks the in-
// memory cache, then, if the config enables "OnDemand", it accesses
// disk, then accesses the network if it must obtain a new certificate
// via ACME.
//
// This method is safe for use as a tls.Config.GetCertificate callback.
func (cfg *Config) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// get the certificate and serve it up
	cert, err := cfg.getCertDuringHandshake(clientHello, true, true)
	return &cert.Certificate, err
}

// getCertificate gets a certificate that matches name from the in-memory
// cache, according to the lookup table associated with cfg. The lookup then
// points to a certificate in the Instance certificate cache.
//
// The name is expected to already be normalized (e.g. lowercased).
//
// If there is no exact match for name, it will be checked against names of
// the form '*.example.com' (wildcard certificates) according to RFC 6125.
// If a match is found, matched will be true. If no matches are found, matched
// will be false and a "default" certificate will be returned with defaulted
// set to true. If defaulted is false, then no certificates were available.
//
// The logic in this function is adapted from the Go standard library,
// which is by the Go Authors.
//
// This function is safe for concurrent use.
func (cfg *Config) getCertificate(hello *tls.ClientHelloInfo) (cert Certificate, matched, defaulted bool) {
	name := NormalizedName(hello.ServerName)

	if name == "" {
		// if SNI is empty, prefer matching IP address
		if hello.Conn != nil {
			addr := hello.Conn.LocalAddr().String()
			ip, _, err := net.SplitHostPort(addr)
			if err == nil {
				addr = ip
			}
			cert, matched = cfg.selectCert(hello, addr)
			if matched {
				return
			}
		}

		// fall back to a "default" certificate, if specified
		if cfg.DefaultServerName != "" {
			normDefault := NormalizedName(cfg.DefaultServerName)
			cert, defaulted = cfg.selectCert(hello, normDefault)
			if defaulted {
				return
			}
		}
	} else {
		// if SNI is specified, try an exact match first
		cert, matched = cfg.selectCert(hello, name)
		if matched {
			return
		}

		// try replacing labels in the name with
		// wildcards until we get a match
		labels := strings.Split(name, ".")
		for i := range labels {
			labels[i] = "*"
			candidate := strings.Join(labels, ".")
			cert, matched = cfg.selectCert(hello, candidate)
			if matched {
				return
			}
		}

		// check the certCache directly to see if the SNI name is
		// already the key of the certificate it wants; this implies
		// that the SNI can contain the hash of a specific cert
		// (chain) it wants and we will still be able to serve it up
		// (this behavior, by the way, could be controversial as to
		// whether it complies with RFC 6066 about SNI, but I think
		// it does, soooo...)
		// (this is how we solved the former ACME TLS-SNI challenge)
		cfg.certCache.mu.RLock()
		directCert, ok := cfg.certCache.cache[name]
		cfg.certCache.mu.RUnlock()
		if ok {
			cert = directCert
			matched = true
			return
		}
	}

	// otherwise, we're bingo on ammo; see issues
	// mholt/caddy#2035 and mholt/caddy#1303 (any
	// change to certificate matching behavior must
	// account for hosts defined where the hostname
	// is empty or a catch-all, like ":443" or
	// "0.0.0.0:443")

	return
}

// selectCert uses hello to select a certificate from the
// cache for name. If cfg.CertSelection is set, it will be
// used to make the decision. Otherwise, the first matching
// unexpired cert is returned.
func (cfg *Config) selectCert(hello *tls.ClientHelloInfo, name string) (Certificate, bool) {
	choices := cfg.certCache.getAllMatchingCerts(name)
	if len(choices) == 0 {
		return Certificate{}, false
	}
	if cfg.CertSelection == nil {
		// by default, choose first non-expired cert
		now := time.Now()
		for _, choice := range choices {
			if now.Before(choice.NotAfter) {
				return choice, true
			}
		}
		// all matching certs are expired, oh well
		return choices[0], true
	}
	cert, err := cfg.CertSelection.SelectCertificate(hello, choices)
	return cert, err == nil
}

// getCertDuringHandshake will get a certificate for hello. It first tries
// the in-memory cache. If no certificate for hello is in the cache, the
// config most closely corresponding to hello will be loaded. If that config
// allows it (OnDemand==true) and if loadIfNecessary == true, it goes to disk
// to load it into the cache and serve it. If it's not on disk and if
// obtainIfNecessary == true, the certificate will be obtained from the CA,
// cached, and served. If obtainIfNecessary is true, then loadIfNecessary
// must also be set to true. An error will be returned if and only if no
// certificate is available.
//
// This function is safe for concurrent use.
func (cfg *Config) getCertDuringHandshake(hello *tls.ClientHelloInfo, loadIfNecessary, obtainIfNecessary bool) (Certificate, error) {
	name := NormalizedName(hello.ServerName)

	// First check our in-memory cache to see if we've already loaded it
	cert, matched, defaulted := cfg.getCertificate(hello)
	if matched {
		return cert, nil
	}

	// Fall back to the default certificate if there is one
	if defaulted {
		return cert, nil
	}

	return Certificate{}, fmt.Errorf("no certificate available for '%s'", name)
}

// NormalizedName returns a cleaned form of serverName that is
// used for consistency when referring to a SNI value.
func NormalizedName(serverName string) string {
	return strings.ToLower(strings.TrimSpace(serverName))
}

func preferredDefaultCipherSuites() []uint16 {
	if cpuid.CPU.AesNi() {
		return defaultCiphersPreferAES
	}
	return defaultCiphersPreferChaCha
}

var (
	defaultCiphersPreferAES = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	defaultCiphersPreferChaCha = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
)

// Manager is a type that can manage a certificate.
// They are usually very short-lived.
type Manager interface {
	Obtain(name string) error
	Renew(name string) error
	Revoke(name string) error
}

// CertificateSelector is a type which can select a certificate to use given multiple choices.
type CertificateSelector interface {
	SelectCertificate(*tls.ClientHelloInfo, []Certificate) (Certificate, error)
}
