package tls

import (
	"crypto/tls"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/mholt/certmagic"
)

func TestParseCertificate_parses_certificate(t *testing.T) {
	cert := createTestCertificateOnDisk(testPrivateKey, testCertContent)
	defer os.Remove(cert)
	certBytes, keyBytes, err := ParseCertificate(cert)
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	if strings.TrimSpace(string(certBytes)) != strings.TrimSpace(testCertContent) {
		t.Fatalf("Expected %s, got %s", testCertContent, string(certBytes))
	}
	if strings.TrimSpace(string(keyBytes)) != strings.TrimSpace(testPrivateKey) {
		t.Fatalf("Expected %s, got %s", testPrivateKey, string(keyBytes))
	}
}

func TestMakeCertificate_returns_cert(t *testing.T) {
	cert, err := makeCertificate([]byte(testCertContent), []byte(testPrivateKey))
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	if cert.Names[0] != "7591*.lagrange.ninja" {
		t.Fatalf("Expected inputted certificate to be returned, got %+v", cert)
	}
}

func TestFillCertFromLeaf_returns_error_when_certificate_is_empty(t *testing.T) {
	cert := tls.Certificate{}
	if err := fillCertFromLeaf(nil, cert); err == nil {
		t.Fatal("Expected an error to be returned")
	}
}

func TestFillCertFromLeaf_returns_error_given_invalid_certifcate(t *testing.T) {
	tlsCert := tls.Certificate{
		Certificate: [][]byte{
			{'b', 'l', 'a', 'h'},
		},
	}
	certmagicCert := &certmagic.Certificate{}
	if err := fillCertFromLeaf(certmagicCert, tlsCert); err == nil {
		t.Fatal("Expected an error to be returned")
	}
}

func TestFillCertFromLeaf_returns_error_given_a_certificate_without_names(t *testing.T) {
	block, _ := pem.Decode([]byte(certBytes2))
	tlsCert := tls.Certificate{
		Certificate: [][]byte{
			block.Bytes,
		},
	}
	certmagicCert := &certmagic.Certificate{}
	err := fillCertFromLeaf(certmagicCert, tlsCert)
	if err != nil {
		t.Fatalf("Unexpected error, %s", err)
	}
	if certmagicCert.Names[0] != "7591*.lagrange.ninja" {
		t.Fatalf("Expected certificate names to be set, got %v", certmagicCert.Names)
	}
}

func createTestCertificateOnDisk(privateKeyPEM, certContentPEM string) string {
	cert, _ := os.Create("cert1.pem")
	content := privateKeyPEM + certContentPEM
	cert.Write([]byte(content))
	return cert.Name()
}

const certBytes2 = `
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
-----END CERTIFICATE-----`

const certBytes = `
-----BEGIN CERTIFICATE-----
MIIF4TCCBMmgAwIBAgIQc+6uFePfrahUGpXs8lhiTzANBgkqhkiG9w0BAQsFADCB
8zELMAkGA1UEBhMCRVMxOzA5BgNVBAoTMkFnZW5jaWEgQ2F0YWxhbmEgZGUgQ2Vy
dGlmaWNhY2lvIChOSUYgUS0wODAxMTc2LUkpMSgwJgYDVQQLEx9TZXJ2ZWlzIFB1
YmxpY3MgZGUgQ2VydGlmaWNhY2lvMTUwMwYDVQQLEyxWZWdldSBodHRwczovL3d3
dy5jYXRjZXJ0Lm5ldC92ZXJhcnJlbCAoYykwMzE1MDMGA1UECxMsSmVyYXJxdWlh
IEVudGl0YXRzIGRlIENlcnRpZmljYWNpbyBDYXRhbGFuZXMxDzANBgNVBAMTBkVD
LUFDQzAeFw0xNDA5MTgwODIxMDBaFw0zMDA5MTgwODIxMDBaMIGGMQswCQYDVQQG
EwJFUzEzMDEGA1UECgwqQ09OU09SQ0kgQURNSU5JU1RSQUNJTyBPQkVSVEEgREUg
Q0FUQUxVTllBMSowKAYDVQQLDCFTZXJ2ZWlzIFDDumJsaWNzIGRlIENlcnRpZmlj
YWNpw7MxFjAUBgNVBAMMDUVDLUNpdXRhZGFuaWEwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDFkHPRZPZlXTWZ5psJhbS/Gx+bxcTpGrlVQHHtIkgGz77y
TA7UZUFb2EQMncfbOhR0OkvQQn1aMvhObFJSR6nI+caf2D+h/m/InMl1MyH3S0Ak
YGZZsthnyC6KxqK2A/NApncrOreh70ULkQs45aOKsi1kR1W0zE+iFN+/P19P7AkL
Rl3bXBCVd8w+DLhcwRrkf1FCDw6cEqaFm3cGgf5cbBDMaVYAweWTxwBZAq2RbQAW
jE7mledcYghcZa4U6bUmCBPuLOnO8KMFAvH+aRzaf3ws5/ZoOVmryyLLJVZ54peZ
OwnP9EL4OuWzmXCjBifXR2IAblxs5JYj57tls45nAgMBAAGjggHaMIIB1jASBgNV
HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUC2hZPofI
oxUa4ECCIl+fHbLFNxUwHwYDVR0jBBgwFoAUoMOLRKo3pUW/l4Ba0fF4opvpXY0w
gdYGA1UdIASBzjCByzCByAYEVR0gADCBvzAxBggrBgEFBQcCARYlaHR0cHM6Ly93
d3cuYW9jLmNhdC9DQVRDZXJ0L1JlZ3VsYWNpbzCBiQYIKwYBBQUHAgIwfQx7QXF1
ZXN0IGNlcnRpZmljYXQgw6lzIGVtw6hzIMO6bmljYSBpIGV4Y2x1c2l2YW1lbnQg
YSBFbnRpdGF0cyBkZSBDZXJ0aWZpY2FjacOzLiBWZWdldSBodHRwczovL3d3dy5h
b2MuY2F0L0NBVENlcnQvUmVndWxhY2lvMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEF
BQcwAYYXaHR0cDovL29jc3AuY2F0Y2VydC5jYXQwYgYDVR0fBFswWTBXoFWgU4Yn
aHR0cDovL2Vwc2NkLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JshihodHRwOi8v
ZXBzY2QyLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JsMA0GCSqGSIb3DQEBCwUA
A4IBAQChqFTjlAH5PyIhLjLgEs68CyNNC1+vDuZXRhy22TI83JcvGmQrZosPvVIL
PsUXx+C06Pfqmh48Q9S89X9K8w1SdJxP/rZeGEoRiKpwvQzM4ArD9QxyC8jirxex
3Umg9Ai/sXQ+1lBf6xw4HfUUr1WIp7pNHj0ZWLo106urqktcdeAFWme+/klis5fu
labCSVPuT/QpwakPrtqOhRms8vgpKiXa/eLtL9ZiA28X/Mker0zlAeTA7Z7uAnp6
oPJTlZu1Gg1ZDJueTWWsLlO+P+Wzm3MRRIbcgdRzm4mdO7ubu26SzX/aQXDhuih+
eVxXDTCfs7GUlxnjOp5j559X/N0A
-----END CERTIFICATE-----
`

const testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
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

const testCertContent = `-----BEGIN CERTIFICATE-----
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
