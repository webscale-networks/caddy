// Copyright 2015 Light Code Labs, LLC
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

package caddytls

import (
	"crypto/tls"
	"os"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy"
	wstls "github.com/caddyserver/caddy/webscale/tls"
	"github.com/klauspost/cpuid"
	"github.com/mholt/certmagic"
)

func TestNewConfigSetsOverrideCache(t *testing.T) {
	inst := &caddy.Instance{
		Storage: make(map[interface{}]interface{}),
	}
	c, err := NewConfig(inst)
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	if c.OverrideCache != nil {
		t.Fatalf("Expected OverrideCache to be nil")
	}
}

func TestGetCertificateCallbackOverrideSet(t *testing.T) {
	// Create and seed the cache.
	url := "webscale.lagrange.ninja"
	cache := wstls.NewAliasKeyedCache()
	if err := loadTestCertificate(cache, url); err != nil {
		t.Fatalf("Unexpected error occurred %s", err)
	}

	// Set override cache.
	c := &Config{}
	c.OverrideCache = cache

	// Remove certmagic's certificate cache lookup.
	c.Manager = nil

	hello := &tls.ClientHelloInfo{
		ServerName: url,
	}

	expectedCert, err := cache.GetCertificate(hello)
	if err != nil {
		t.Fatalf("Unexpected error occurred %s", err)
	}
	actualCert, err := c.getCertificateCallback()(hello)
	if err != nil {
		t.Fatalf("Unexpected error occurred %s", err)
	}
	if !reflect.DeepEqual(expectedCert, actualCert) {
		t.Fatalf("Expected %+v, got %+v", expectedCert, actualCert)
	}
}

func TestGetCertificateCertmagicCache(t *testing.T) {
	inst := &caddy.Instance{
		Storage: make(map[interface{}]interface{}),
	}
	c, err := NewConfig(inst)
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}

	c.OverrideCache = nil
	d := &DummyCertSelection{
		called: false,
	}
	c.Manager.CertSelection = d
	c.Manager.CacheUnmanagedCertificatePEMBytes([]byte(certBytes), []byte(keyBytes), []string{})

	url := "7591*.lagrange.ninja"
	hello := &tls.ClientHelloInfo{
		ServerName: url,
	}
	c.getCertificateCallback()(hello)
	if !d.called {
		t.Fatal("Expected certmagic lookup to be called")
	}
}

func TestConvertTLSConfigProtocolVersions(t *testing.T) {
	// same min and max protocol versions
	config := &Config{
		Enabled:            true,
		ProtocolMinVersion: tls.VersionTLS12,
		ProtocolMaxVersion: tls.VersionTLS12,
	}
	err := config.buildStandardTLSConfig()
	if err != nil {
		t.Fatalf("Did not expect an error, but got %v", err)
	}
	if got, want := config.tlsConfig.MinVersion, uint16(tls.VersionTLS12); got != want {
		t.Errorf("Expected min version to be %x, got %x", want, got)
	}
	if got, want := config.tlsConfig.MaxVersion, uint16(tls.VersionTLS12); got != want {
		t.Errorf("Expected max version to be %x, got %x", want, got)
	}
}

func TestConvertTLSConfigPreferServerCipherSuites(t *testing.T) {
	// prefer server cipher suites
	config := Config{Enabled: true, PreferServerCipherSuites: true}
	err := config.buildStandardTLSConfig()
	if err != nil {
		t.Fatalf("Did not expect an error, but got %v", err)
	}
	if got, want := config.tlsConfig.PreferServerCipherSuites, true; got != want {
		t.Errorf("Expected PreferServerCipherSuites==%v but got %v", want, got)
	}
}

func TestMakeTLSConfigTLSEnabledDisabledError(t *testing.T) {
	// verify handling when Enabled is true and false
	configs := []*Config{
		{Enabled: true},
		{Enabled: false},
	}
	_, err := MakeTLSConfig(configs)
	if err == nil {
		t.Fatalf("Expected an error, but got %v", err)
	}
}

func TestConvertTLSConfigCipherSuites(t *testing.T) {
	// ensure cipher suites are unioned and
	// that TLS_FALLBACK_SCSV is prepended
	configs := []*Config{
		{Enabled: true, Ciphers: []uint16{0xc02c, 0xc030}},
		{Enabled: true, Ciphers: []uint16{0xc012, 0xc030, 0xc00a}},
		{Enabled: true, Ciphers: nil},
	}

	defaultCiphersExpected := getPreferredDefaultCiphers()
	expectedCiphers := [][]uint16{
		{tls.TLS_FALLBACK_SCSV, 0xc02c, 0xc030},
		{tls.TLS_FALLBACK_SCSV, 0xc012, 0xc030, 0xc00a},
		append([]uint16{tls.TLS_FALLBACK_SCSV}, defaultCiphersExpected...),
	}

	for i, config := range configs {
		err := config.buildStandardTLSConfig()
		if err != nil {
			t.Errorf("Test %d: Expected no error, got: %v", i, err)
		}
		if !reflect.DeepEqual(config.tlsConfig.CipherSuites, expectedCiphers[i]) {
			t.Errorf("Test %d: Expected ciphers %v but got %v",
				i, expectedCiphers[i], config.tlsConfig.CipherSuites)
		}

	}
}

func TestGetPreferredDefaultCiphers(t *testing.T) {
	expectedCiphers := defaultCiphers
	if !cpuid.CPU.AesNi() {
		expectedCiphers = defaultCiphersNonAESNI
	}

	// Ensure ordering is correct and ciphers are what we expected.
	result := getPreferredDefaultCiphers()
	for i, actual := range result {
		if actual != expectedCiphers[i] {
			t.Errorf("Expected cipher in position %d to be %0x, got %0x", i, expectedCiphers[i], actual)
		}
	}
}

func TestAssertTLSConfigCompatibleClientCert(t *testing.T) {
	configs := []*Config{
		{Enabled: true, ClientAuth: tls.RequestClientCert, ClientCerts: []string{}},
		{Enabled: true, ClientAuth: tls.RequestClientCert, ClientCerts: []string{"ca_cert.crt"}},
	}

	_, err := MakeTLSConfig(configs)
	if err == nil {
		t.Fatalf("Expected an error, but got %v", err)
	}

	configs = []*Config{
		{Enabled: true, ClientAuth: tls.RequestClientCert, ClientCerts: []string{"ca_cert.crt"}},
		{Enabled: true, ClientAuth: tls.RequestClientCert, ClientCerts: []string{"ca_cert.crt"}},
	}

	_, err = MakeTLSConfig(configs)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}
}

func loadTestCertificate(cache *wstls.AliasKeyedCache, url string) error {
	cert, err := os.Create("cert1.pem")
	if err != nil {
		return err
	}
	defer os.Remove(cert.Name())
	content := keyBytes + certBytes
	cert.Write([]byte(content))
	return cache.Load(cert.Name(), []string{url})
}

type DummyCertSelection struct {
	called bool
}

func (d *DummyCertSelection) SelectCertificate(*tls.ClientHelloInfo, []certmagic.Certificate) (certmagic.Certificate, error) {
	d.called = true
	return certmagic.Certificate{}, nil
}

var keyBytes = `-----BEGIN RSA PRIVATE KEY-----
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
`

var certBytes = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`
