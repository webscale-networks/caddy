package tls

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestHasTag(t *testing.T) {
	tags := []string{"webscale", "is", "cool"}
	cm := CertMetadata{
		Tags: tags,
	}
	if !cm.HasTag("webscale") ||
		!cm.HasTag("is") ||
		!cm.HasTag("cool") ||
		cm.HasTag("lagrange") {
		t.Fatalf("Expected tags of %v, got %v", tags, cm.Tags)
	}
}

func TestParseCertificate_parses_certificate(t *testing.T) {
	cert, err := os.Create("cert1.pem")
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	defer os.Remove(cert.Name())
	privateKey := `-----BEGIN RSA PRIVATE KEY-----
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
	certContent := `-----BEGIN CERTIFICATE-----
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
	content := privateKey + certContent
	cert.Write([]byte(content))
	certBytes, keyBytes, err := ParseCertificate(cert.Name())
	if err != nil {
		t.Fatalf("Unexpected error %s", err)
	}
	if strings.TrimSpace(string(certBytes)) != strings.TrimSpace(certContent) {
		t.Fatalf("Expected %s, got %s", certContent, string(certBytes))
	}
	if strings.TrimSpace(string(keyBytes)) != strings.TrimSpace(privateKey) {
		t.Fatalf("Expected %s, got %s", privateKey, string(keyBytes))
	}
}

func TestHashCertificateChain(t *testing.T) {
	chain := [][]byte{{'a', 'b', 'c'}, {'x', 'y', 'z'}}
	h := sha256.New()
	for _, cert := range chain {
		h.Write(cert)
	}
	expected := fmt.Sprintf("%x", h.Sum(nil))

	actual := hashCertificateChain(chain)
	if expected != actual {
		t.Fatalf("Expected %s, got %s", expected, actual)
	}
}
