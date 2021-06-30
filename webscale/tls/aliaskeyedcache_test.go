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
	cert, err := os.Create("cert1.pem")
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	defer os.Remove(cert.Name())
	content :=
		`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQChxPY4u7R8EMpQjMSwkKrnEd3wLGaz9Zm2HmQi2x
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICLjCCAZcCAQEwDQYJKoZIhvcNAQEFBQAwWzELMAkGA1UEBhMCVVMxDTALBgNV
-----END CERTIFICATE-----
}`
	cert.Write([]byte(content))

	cache := NewAliasKeyedCache()
	err = cache.Load(cert.Name(), []string{"example.com"})
	if err == nil {
		t.Fatalf("Expect an error due to an invalid PEM file")
	}
}

func TestLoad_stores_certificate_for_aliases(t *testing.T) {
	cert, err := os.Create("cert1.pem")
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	defer os.Remove(cert.Name())
	content :=
		`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQChxPYdRkkmetH2K4u7R8EMpQjMSwkKrnEd3wLGaz9Zm2HmQi2x
wqYgi2i4bCsZp2biWapH9uD+gpmcYfnDb1Fk5CbdS4ZAKwVUWU/Los4FOvxXtK+6
hEcPRtpQJ95xa27vqO6qFzG2ez0f1jx153IyYwJ/WtlawUTwTxhUkiGbSQIDAQAB
AoGABgXXQ+/B+XTJLGkioq5hOZ9LXI/Onl8wRvRungSQLz3hvzjnip68oKmQFI2y
bRoWcob0GAnRBqjGH1RmgCg8132f0PfWXD+xMKwEM2ut8PeEbW8b98KEswgud22K
q8hJBERvB0WSC+h+N+IGJBK8d8AvUlyVeOjIUk0Xs7PLMIECQQDMBwTKh1GwZWo1
RYoK6Wfr6g9xkhlXEQ+wmzn0uDrIxPP6NICKt7SFLTiRshQVFcZ+wwjCbVGdK9Cy
XoZNitCdAkEAyvo5EJgaVEiVqPwL40qG6ci9ZjibdcQaxe6M91XqyMU0L6PzWSNm
aoIDx6+DTbAYTvEjFy4v7xcfC08gKCrnnQJBAKMqyc4ewlnMAVBxOKDZYV7uZUNy
kAltf5rByWvJGloOCQCElHhbymbnb2I1hJIIRCKEX7D+NFL6A4Fizw2cgpECQQCB
mMoeoj8NWVrVDji44rjJQ/ZJ8hKwWomNnwY6VY0Wq3LqiA+z9jpJ/sFTGekIDUs3
/Bafkkngqi6UFe0+OEaxAkA5GnIgnQaIToj28vpax//p1AnA4i/te1cYKaJzBZpy
lP41So/Dpf1UIW6GmZo2w4PVKj3hc6/FUegVLmQxZffD
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICLjCCAZcCAQEwDQYJKoZIhvcNAQEFBQAwWzELMAkGA1UEBhMCVVMxDTALBgNV
BAgMBE9oaW8xETAPBgNVBAcMCENvbHVtYnVzMRAwDgYDVQQKDAdNeUNlcnRzMRgw
FgYDVQQDDA93d3cubXljZXJ0cy5jb20wHhcNMjEwNDIzMjIwMDM4WhcNMjIwNDIz
MjIwMDM4WjBkMQswCQYDVQQGEwJVUzERMA8GA1UECAwIQ29sb3JhZG8xEDAOBgNV
BAcMB0JvdWxkZXIxETAPBgNVBAoMCFdlYnNjYWxlMR0wGwYDVQQDDBQ3NTkxKi5s
YWdyYW5nZS5uaW5qYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAocT2HUZJ
JnrR9iuLu0fBDKUIzEsJCq5xHd8Cxms/WZth5kItscKmIItouGwrGadm4lmqR/bg
/oKZnGH5w29RZOQm3UuGQCsFVFlPy6LOBTr8V7SvuoRHD0baUCfecWtu76juqhcx
tns9H9Y8dedyMmMCf1rZWsFE8E8YVJIhm0kCAwEAATANBgkqhkiG9w0BAQUFAAOB
gQCV0nzUudq58dwZBbVG0U8dIQ+Fb4f/WUYcr9F3q3o4A4tXN5xGXRqbtqyERT/J
dnJycx1mp+X6hiTXJaajhEy+ljhz+ubJmIrpRUh+fhxboI5ml5O1J+hdrFP2He0/
9AwI9B05dYBoizG3WuXll8ctbQE1eDi70GzSyQ5gflpyDw==
-----END CERTIFICATE-----
	`
	cert.Write([]byte(content))
	cache := NewAliasKeyedCache()
	err = cache.Load(cert.Name(), []string{"example.com"})
	if err != nil {
		t.Fatalf("Unexpected error, %s", err)
	}

	if cache.cache["example.com"] == nil {
		t.Fatal("Expected 'example.com' alias to be associated to a certificate")
	}
}

func TestSetDefaultCertificate_returns_error_given_invalid_file(t *testing.T) {
	cert, err := os.Create("cert1.pem")
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	defer os.Remove(cert.Name())
	content :=
		`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQChxPY4u7R8EMpQjMSwkKrnEd3wLGaz9Zm2HmQi2x
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICLjCCAZcCAQEwDQYJKoZIhvcNAQEFBQAwWzELMAkGA1UEBhMCVVMxDTALBgNV
-----END CERTIFICATE-----
}`
	cert.Write([]byte(content))

	cache := NewAliasKeyedCache()
	err = cache.SetDefaultCertificate(cert.Name())
	if err == nil {
		t.Fatalf("Expect an error due to an invalid PEM file")
	}
}

func TestSetDefaultCertificate_stores_default(t *testing.T) {
	cert, err := os.Create("cert1.pem")
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	defer os.Remove(cert.Name())
	content :=
		`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQChxPYdRkkmetH2K4u7R8EMpQjMSwkKrnEd3wLGaz9Zm2HmQi2x
wqYgi2i4bCsZp2biWapH9uD+gpmcYfnDb1Fk5CbdS4ZAKwVUWU/Los4FOvxXtK+6
hEcPRtpQJ95xa27vqO6qFzG2ez0f1jx153IyYwJ/WtlawUTwTxhUkiGbSQIDAQAB
AoGABgXXQ+/B+XTJLGkioq5hOZ9LXI/Onl8wRvRungSQLz3hvzjnip68oKmQFI2y
bRoWcob0GAnRBqjGH1RmgCg8132f0PfWXD+xMKwEM2ut8PeEbW8b98KEswgud22K
q8hJBERvB0WSC+h+N+IGJBK8d8AvUlyVeOjIUk0Xs7PLMIECQQDMBwTKh1GwZWo1
RYoK6Wfr6g9xkhlXEQ+wmzn0uDrIxPP6NICKt7SFLTiRshQVFcZ+wwjCbVGdK9Cy
XoZNitCdAkEAyvo5EJgaVEiVqPwL40qG6ci9ZjibdcQaxe6M91XqyMU0L6PzWSNm
aoIDx6+DTbAYTvEjFy4v7xcfC08gKCrnnQJBAKMqyc4ewlnMAVBxOKDZYV7uZUNy
kAltf5rByWvJGloOCQCElHhbymbnb2I1hJIIRCKEX7D+NFL6A4Fizw2cgpECQQCB
mMoeoj8NWVrVDji44rjJQ/ZJ8hKwWomNnwY6VY0Wq3LqiA+z9jpJ/sFTGekIDUs3
/Bafkkngqi6UFe0+OEaxAkA5GnIgnQaIToj28vpax//p1AnA4i/te1cYKaJzBZpy
lP41So/Dpf1UIW6GmZo2w4PVKj3hc6/FUegVLmQxZffD
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICLjCCAZcCAQEwDQYJKoZIhvcNAQEFBQAwWzELMAkGA1UEBhMCVVMxDTALBgNV
BAgMBE9oaW8xETAPBgNVBAcMCENvbHVtYnVzMRAwDgYDVQQKDAdNeUNlcnRzMRgw
FgYDVQQDDA93d3cubXljZXJ0cy5jb20wHhcNMjEwNDIzMjIwMDM4WhcNMjIwNDIz
MjIwMDM4WjBkMQswCQYDVQQGEwJVUzERMA8GA1UECAwIQ29sb3JhZG8xEDAOBgNV
BAcMB0JvdWxkZXIxETAPBgNVBAoMCFdlYnNjYWxlMR0wGwYDVQQDDBQ3NTkxKi5s
YWdyYW5nZS5uaW5qYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAocT2HUZJ
JnrR9iuLu0fBDKUIzEsJCq5xHd8Cxms/WZth5kItscKmIItouGwrGadm4lmqR/bg
/oKZnGH5w29RZOQm3UuGQCsFVFlPy6LOBTr8V7SvuoRHD0baUCfecWtu76juqhcx
tns9H9Y8dedyMmMCf1rZWsFE8E8YVJIhm0kCAwEAATANBgkqhkiG9w0BAQUFAAOB
gQCV0nzUudq58dwZBbVG0U8dIQ+Fb4f/WUYcr9F3q3o4A4tXN5xGXRqbtqyERT/J
dnJycx1mp+X6hiTXJaajhEy+ljhz+ubJmIrpRUh+fhxboI5ml5O1J+hdrFP2He0/
9AwI9B05dYBoizG3WuXll8ctbQE1eDi70GzSyQ5gflpyDw==
-----END CERTIFICATE-----
	`
	cert.Write([]byte(content))
	cache := NewAliasKeyedCache()
	err = cache.SetDefaultCertificate(cert.Name())
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
