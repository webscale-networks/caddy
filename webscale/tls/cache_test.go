package tls

import (
	"reflect"
	"testing"
)

func TestNewCache(t *testing.T) {
	c := NewCache()
	if c.cache == nil ||
		c.cacheIndex == nil {
		t.Fatalf("Expected a fully initialized cache, got %v", c)
	}
}

func TestCacheCertificate(t *testing.T) {
	certCache := &Cache{cache: make(map[string]Certificate), cacheIndex: make(map[string][]string)}

	certCache.cacheCertificate(Certificate{Names: []string{"example.com", "sub.example.com"}, hash: "foobar"})
	if len(certCache.cache) != 1 {
		t.Errorf("Expected length of certificate cache to be 1")
	}
	if _, ok := certCache.cache["foobar"]; !ok {
		t.Error("Expected first cert to be cached by key 'foobar', but it wasn't")
	}
	if _, ok := certCache.cacheIndex["example.com"]; !ok {
		t.Error("Expected first cert to be keyed by 'example.com', but it wasn't")
	}
	if _, ok := certCache.cacheIndex["sub.example.com"]; !ok {
		t.Error("Expected first cert to be keyed by 'sub.example.com', but it wasn't")
	}

	// using same cache; and has cert with overlapping name, but different hash
	certCache.cacheCertificate(Certificate{Names: []string{"example.com"}, hash: "barbaz"})
	if _, ok := certCache.cache["barbaz"]; !ok {
		t.Error("Expected second cert to be cached by key 'barbaz.com', but it wasn't")
	}
	if hashes, ok := certCache.cacheIndex["example.com"]; !ok {
		t.Error("Expected second cert to be keyed by 'example.com', but it wasn't")
	} else if !reflect.DeepEqual(hashes, []string{"foobar", "barbaz"}) {
		t.Errorf("Expected second cert to map to 'barbaz' but it was %v instead", hashes)
	}
}

func TestUnsyncedCacheCertificate(t *testing.T) {
	c := NewCache()

	// Add certificate test.
	hash := "1"
	names := []string{"webscale"}
	cert := Certificate{
		CertMetadata: CertMetadata{
			Tags: []string{"first"},
		},
		hash:  hash,
		Names: names,
	}
	c.unsyncedCacheCertificate(cert)
	if !reflect.DeepEqual(c.cache[hash], cert) {
		t.Fatalf("Expected certificate to be stored")
	}
	if c.cacheIndex["webscale"][0] != cert.hash {
		t.Fatalf("Expected certificate names to be added to cacheIndex")
	}

	// Do not re-add a certificate already in cache as determined by the hash.
	cert2 := Certificate{
		CertMetadata: CertMetadata{
			Tags: []string{"second"},
		},
		hash: hash,
	}
	c.unsyncedCacheCertificate(cert2)
	if !reflect.DeepEqual(c.cache[hash], cert) {
		t.Fatalf("Expected certificate to be stored")
	}
}

func TestGetAllMatchingCerts(t *testing.T) {
	c := NewCache()
	hash := "1"
	names := []string{"webscale"}
	cert := Certificate{
		hash:  hash,
		Names: names,
	}
	c.unsyncedCacheCertificate(cert)
	certs := c.getAllMatchingCerts("webscale")
	if len(certs) < 1 {
		t.Fatalf("Expected a certificate to be returned")
	}
	if !reflect.DeepEqual(certs[0], cert) {
		t.Fatalf("Expected %v, got %v", cert, certs[0])
	}
}
