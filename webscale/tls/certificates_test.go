package tls

import (
	"crypto/sha256"
	"fmt"
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
