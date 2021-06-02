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
	"sync"
)

// Cache is a structure that stores certificates in memory.
// A Cache indexes certificates by name for quick access
// during TLS handshakes, and avoids duplicating certificates
// in memory. Generally, there should only be one per process.
// However, that is not a strict requirement; but using more
// than one is a code smell, and may indicate an
// over-engineered design.
//
// An empty cache is INVALID and must not be used. Be sure
// to call NewCache to get a valid value.
//
// These should be very long-lived values and must not be
// copied. Before all references leave scope to be garbage
// collected, ensure you call Stop() to stop maintenance on
// the certificates stored in this cache and release locks.
//
// Caches are not usually manipulated directly; create a
// Config value with a pointer to a Cache, and then use
// the Config to interact with the cache. Caches are
// agnostic of any particular storage or ACME config,
// since each certificate may be managed and stored
// differently.
type Cache struct {
	// The cache is keyed by certificate hash
	cache map[string]Certificate

	// cacheIndex is a map of SAN to cache key (cert hash)
	cacheIndex map[string][]string

	// Protects the cache and index maps
	mu sync.RWMutex
}

// NewCache returns a new, valid Cache for efficiently
// accessing certificates in memory. Call Stop() when
// you are done with the cache so it can clean up
// locks and stuff.
//
// Most users of this package will not need to call this
// because a default certificate cache is created for you.
// Only advanced use cases require creating a new cache.
//
// See the godoc for Cache to use it properly. When
// no longer needed, caches should be stopped with
// Stop() to clean up resources even if the process
// is being terminated, so that it can clean up
// any locks for other processes to unblock!
func NewCache() *Cache {
	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
	}

	return c
}

// cacheCertificate calls unsyncedCacheCertificate with a write lock.
//
// This function is safe for concurrent use.
func (certCache *Cache) cacheCertificate(cert Certificate) {
	certCache.mu.Lock()
	certCache.unsyncedCacheCertificate(cert)
	certCache.mu.Unlock()
}

// unsyncedCacheCertificate adds cert to the in-memory cache unless
// it already exists in the cache (according to cert.Hash). It
// updates the name index.
//
// This function is NOT safe for concurrent use. Callers MUST acquire
// a write lock on certCache.mu first.
func (certCache *Cache) unsyncedCacheCertificate(cert Certificate) {
	// no-op if this certificate already exists in the cache
	if _, ok := certCache.cache[cert.hash]; ok {
		return
	}

	// store the certificate
	certCache.cache[cert.hash] = cert

	// update the index so we can access it by name
	for _, name := range cert.Names {
		certCache.cacheIndex[name] = append(certCache.cacheIndex[name], cert.hash)
	}
}

func (certCache *Cache) getAllMatchingCerts(name string) []Certificate {
	certCache.mu.RLock()
	defer certCache.mu.RUnlock()

	allCertKeys := certCache.cacheIndex[name]

	certs := make([]Certificate, len(allCertKeys))
	for i := range allCertKeys {
		certs[i] = certCache.cache[allCertKeys[i]]
	}

	return certs
}

var (
	defaultCache   *Cache
	defaultCacheMu sync.Mutex
)
