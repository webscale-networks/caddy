package tls

import (
	"crypto/tls"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/mholt/certmagic"
)

func TestNewAliasKeyedCache_returns_initialized_cache(t *testing.T) {
	cache := NewAliasKeyedCache()
	if cache.cache == nil {
		t.Fatalf("Expected an initialized cache to be returned, got %+v", cache)
	}
}

func TestNewAliasKeyedCache_set_defaultCertificate_to_nil(t *testing.T) {
	cache := NewAliasKeyedCache()
	if cache.defaultCertificate != nil {
		t.Fatalf("Expected an initialized cache defaultCertificate to be nil, got %+v", cache)
	}
}

func TestLoad_returns_error_given_invalid_file(t *testing.T) {
	pk := `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQChxPY4u7R8EMpQjMSwkKrnEd3wLGaz9Zm2HmQi2x
-----END RSA PRIVATE KEY-----
`
	certContent := `-----BEGIN CERTIFICATE-----
MIICLjCCAZcCAQEwDQYJKoZIhvcNAQEFBQAwWzELMAkGA1UEBhMCVVMxDTALBgNV
-----END CERTIFICATE-----
`
	cert := createTestCertificateOnDisk(pk, certContent)
	defer os.Remove(cert)

	cache := NewAliasKeyedCache()
	err := cache.Load(cert, []string{"example.com"})
	if err == nil {
		t.Fatalf("Expect an error due to an invalid PEM file")
	}
}

func TestLoad_stores_certificate_for_aliases(t *testing.T) {
	cert := createTestCertificateOnDisk(testPrivateKey, testCertContent)
	defer os.Remove(cert)
	cache := NewAliasKeyedCache()
	err := cache.Load(cert, []string{"example.com"})
	if err != nil {
		t.Fatalf("Unexpected error, %s", err)
	}

	if cache.cache["example.com"] == nil {
		t.Fatal("Expected 'example.com' alias to be associated to a certificate")
	}
}

func TestSetDefaultCertificate_returns_error_given_invalid_file(t *testing.T) {
	pk := `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQChxPY4u7R8EMpQjMSwkKrnEd3wLGaz9Zm2HmQi2x
-----END RSA PRIVATE KEY-----
`
	certContent := `-----BEGIN CERTIFICATE-----
MIICLjCCAZcCAQEwDQYJKoZIhvcNAQEFBQAwWzELMAkGA1UEBhMCVVMxDTALBgNV
-----END CERTIFICATE-----
`
	cert := createTestCertificateOnDisk(pk, certContent)
	defer os.Remove(cert)

	cache := NewAliasKeyedCache()
	err := cache.SetDefaultCertificate(cert)
	if err == nil {
		t.Fatalf("Expect an error due to an invalid PEM file")
	}
}

func TestSetDefaultCertificate_stores_default(t *testing.T) {
	cert := createTestCertificateOnDisk(testPrivateKey, testCertContent)
	defer os.Remove(cert)
	cache := NewAliasKeyedCache()
	err := cache.SetDefaultCertificate(cert)
	if err != nil {
		t.Fatalf("Unexpected error, %s", err)
	}

	if cache.defaultCertificate == nil {
		t.Fatal("Expected default certificate to be set")
	}
}

func TestGetCertificate_returns_default_certificate_when_alias_not_found(t *testing.T) {
	cache := NewAliasKeyedCache()
	defaultCert := &certmagic.Certificate{
		Certificate: tls.Certificate{},
		NotAfter:    time.Now().Add(1 * time.Hour),
	}
	cache.defaultCertificate = defaultCert

	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}
	expectedCert := &defaultCert.Certificate
	actualCert, err := cache.GetCertificate(hello)
	if err != nil {
		t.Fatalf("Unexpected error, %s", err)
	}
	if !reflect.DeepEqual(expectedCert, actualCert) {
		t.Fatalf("Expected %+v, got %+v", expectedCert, actualCert)
	}
}

func TestGetCertificate_returns_associated_certificate_for_alias(t *testing.T) {
	cache := NewAliasKeyedCache()
	aliasCert := &certmagic.Certificate{
		Certificate: tls.Certificate{},
		NotAfter:    time.Now().Add(1 * time.Hour),
	}
	alias := "example.com"
	cache.cache[alias] = aliasCert

	hello := &tls.ClientHelloInfo{
		ServerName: alias,
	}

	expectedCert := &aliasCert.Certificate
	actualCert, err := cache.GetCertificate(hello)
	if err != nil {
		t.Fatalf("Unexpected error, %s", err)
	}
	if !reflect.DeepEqual(actualCert, expectedCert) {
		t.Fatalf("Expected default certificate to be returned, got %+v", actualCert)
	}
}

func TestGetCertificate_returns_default_certificate_when_alias_certificate_is_expired(t *testing.T) {
	cache := NewAliasKeyedCache()
	cache.defaultCertificate = &certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{{'x', 'y', 'z'}},
		},
		NotAfter: time.Now().AddDate(1, 1, 1),
	}
	aliasCert := &certmagic.Certificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{
				{'a', 'b', 'c'},
			},
		},
		NotAfter: time.Now().AddDate(-1, -1, -1),
	}
	alias := "example.com"
	cache.cache[alias] = aliasCert

	hello := &tls.ClientHelloInfo{
		ServerName: alias,
	}

	expectedCert := &cache.defaultCertificate.Certificate
	actualCert, err := cache.GetCertificate(hello)
	if err != nil {
		t.Fatalf("Unexpected error, %s", err)
	}
	if !reflect.DeepEqual(actualCert, expectedCert) {
		t.Fatalf("Expected default certificate to be returned, got %+v", actualCert)
	}
}

func TestGetCertificate_returns_error_when_all_certificates_are_expired(t *testing.T) {
	cache := NewAliasKeyedCache()
	cache.defaultCertificate = &certmagic.Certificate{
		NotAfter: time.Now().AddDate(0, -1, 0),
	}
	aliasCert := &certmagic.Certificate{
		NotAfter: time.Now().AddDate(0, -1, 0),
	}
	alias := "example.com"
	cache.cache[alias] = aliasCert

	hello := &tls.ClientHelloInfo{
		ServerName: alias,
	}
	_, err := cache.GetCertificate(hello)
	if err == nil {
		t.Fatal("Expected an error due to all certificates being expired")
	}
}
