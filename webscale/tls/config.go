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
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

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

	// Pointer to the in-memory certificate cache. This cache is keyed on the
	// names in a certificate.
	certCache *NameKeyedCache

	// Pointer to in-memory certificate cache to use instead of certCache.
	// When non-nil, this cache is used instead of certCache for certificate
	// lookups. This cache is keyed on hostname aliases. These alias-certificate
	// associations are detailed in 'strict_tls' directive of the Caddyfile. The
	// certificate that is served is the one that matches the SNI in the
	// client's hello message during the TLS handshake, regardless of whether or
	// not the certificate covers the alias.
	OverrideCache *AliasKeyedCache
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
		defaultCache = NewNameKeyedCache()
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
// that may differ from the Default. However, for
// the vast majority of cases, there will be only a
// single Config, thus the default cache (which always
// uses the default Config) and default config will
// suffice, and you should use New() instead.
func New(certCache *NameKeyedCache, cfg Config) *Config {
	if certCache == nil {
		panic("a certificate cache is required")
	}
	return newWithCache(certCache, cfg)
}

// newWithCache ensures that cfg is a valid config by populating
// zero-value fields from the Default Config. If certCache is
// nil, this function panics.
func newWithCache(certCache *NameKeyedCache, cfg Config) *Config {
	if certCache == nil {
		panic("cannot make a valid config without a pointer to a certificate cache")
	}

	// fill in default values
	if cfg.DefaultServerName == "" {
		cfg.DefaultServerName = Default.DefaultServerName
	}

	// ensure the unexported fields are valid
	cfg.certCache = certCache

	// By default, do not override the certificate cache.
	cfg.OverrideCache = nil

	return &cfg
}

// GetCertificate gets a certificate to satisfy clientHello. If the config's
// cache override is set, that cache is used instead of the default
// name-keyed-cache.
//
// This method is safe for use as a tls.Config.GetCertificate callback.
func (cfg *Config) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cfg.OverrideCache != nil {
		cert, err := cfg.OverrideCache.getCertificate(clientHello)
		if err != nil {
			return nil, err
		}
		return &cert.Certificate, nil
	}
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

// getCertDuringHandshake will get a certificate for hello.
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

// CertificateSelector is a type which can select a certificate to use given multiple choices.
type CertificateSelector interface {
	SelectCertificate(*tls.ClientHelloInfo, []Certificate) (Certificate, error)
}
