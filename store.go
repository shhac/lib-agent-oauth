// Package oauth implements the local OAuth 2.1 layer for lib-agent-mcp's HTTP
// transport: the server is its own Authorization Server and Resource Server, so
// a remote MCP client can complete the OAuth handshake the connector UI requires
// without a third party. See lib-agent-mcp/design-docs/oauth.md for the design.
//
// This file is the storage seam. The layer never reaches into a CLI's own
// credential store; its secrets (the token-signing key, the pairing code, client
// registrations, refresh tokens) live in their own SecretStore, by default the
// host keyring under a namespace distinct from the CLI's API credentials.
package oauth

import (
	"errors"
	"sync"

	keyring "github.com/shhac/lib-agent-keyring"
)

// ErrStoreUnavailable is returned by a SecretStore that has no usable backend —
// e.g. the keyring store on a headless host with no OS secret service. Local
// OAuth needs durable storage for its signing key, so this is fatal to it.
var ErrStoreUnavailable = errors.New("oauth secret store unavailable")

// SecretStore persists the OAuth layer's secrets and state, keyed by an opaque
// string. It is deliberately tiny so any backend fits — the default is the host
// keyring; tests use an in-memory map. The lib never assumes a particular
// backend, keeping it free of any dependency on a CLI's credential subsystem.
type SecretStore interface {
	// Get returns the value for key and whether it was present.
	Get(key string) (value string, ok bool, err error)
	// Set stores value for key, replacing any existing entry.
	Set(key, value string) error
	// Delete removes key (absent key is not an error).
	Delete(key string) error
}

// KeyringStore is a SecretStore backed by the host OS secret store
// (lib-agent-keyring), under its own service namespace — separate from any CLI
// API-credential service, so the two trust axes stay independent.
type KeyringStore struct{ kr *keyring.Keyring }

// NewKeyringStore returns a KeyringStore for the given keyring service id (the
// namespace), e.g. "app.example.agent-foo.mcp".
func NewKeyringStore(service string) *KeyringStore {
	return &KeyringStore{kr: keyring.New(service)}
}

// Available reports whether the underlying keyring can be used. Local OAuth
// should refuse to start when this is false rather than lose its signing key.
func (s *KeyringStore) Available() bool { return s.kr.Available() }

// ensureAvailable is the single availability guard the three methods share, so
// the unavailable-store contract can't drift between them.
func (s *KeyringStore) ensureAvailable() error {
	if !s.kr.Available() {
		return ErrStoreUnavailable
	}
	return nil
}

func (s *KeyringStore) Get(key string) (string, bool, error) {
	if err := s.ensureAvailable(); err != nil {
		return "", false, err
	}
	v, ok := s.kr.Get(key)
	return v, ok, nil
}

func (s *KeyringStore) Set(key, value string) error {
	if err := s.ensureAvailable(); err != nil {
		return err
	}
	return s.kr.Set(key, value)
}

func (s *KeyringStore) Delete(key string) error {
	if err := s.ensureAvailable(); err != nil {
		return err
	}
	return s.kr.Delete(key)
}

// DeleteAll removes every secret under the service namespace — the signing key,
// pairing code, client registrations, and refresh tokens. It is the "reset to a
// clean slate" operation: the next server boot regenerates a fresh signing key
// and pairing code, and every client must re-register and re-pair.
func (s *KeyringStore) DeleteAll() error {
	if err := s.ensureAvailable(); err != nil {
		return err
	}
	return s.kr.DeleteAll()
}

// MemStore is an in-memory SecretStore for tests. It is safe for concurrent use.
type MemStore struct {
	mu sync.RWMutex
	m  map[string]string
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore { return &MemStore{m: map[string]string{}} }

func (s *MemStore) Get(key string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[key]
	return v, ok, nil
}

func (s *MemStore) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = value
	return nil
}

func (s *MemStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

// DeleteAll clears every key, mirroring KeyringStore.DeleteAll so tests can
// exercise the `pair reset` wipe without a real keyring.
func (s *MemStore) DeleteAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = map[string]string{}
	return nil
}
