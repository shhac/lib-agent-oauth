package oauth

import (
	"encoding/json"
	"sync"
)

// jsonMapStore persists a map[string]V as one JSON document under a single
// SecretStore key, serializing the load-modify-save with a mutex. It is the
// shared machinery behind the client registry and the refresh-token store, so
// the empty-map handling and locking discipline live in one place.
type jsonMapStore[V any] struct {
	store SecretStore
	key   string
	mu    sync.Mutex
}

// get returns the value for k and whether it is present.
func (s *jsonMapStore[V]) get(k string) (V, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		var zero V
		return zero, false, err
	}
	v, ok := m[k]
	return v, ok, nil
}

// mutate runs fn against the stored map under the lock, then persists the result
// — the atomic read-modify-write both registries are built on.
func (s *jsonMapStore[V]) mutate(fn func(m map[string]V) (changed bool)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	if !fn(m) {
		return nil
	}
	return s.save(m)
}

// load returns the stored map, or an empty map when the key is absent/empty.
func (s *jsonMapStore[V]) load() (map[string]V, error) {
	v, ok, err := s.store.Get(s.key)
	if err != nil {
		return nil, err
	}
	if !ok || v == "" {
		return map[string]V{}, nil
	}
	var m map[string]V
	if err := json.Unmarshal([]byte(v), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// save writes the whole map back under the key.
func (s *jsonMapStore[V]) save(m map[string]V) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.store.Set(s.key, string(b))
}
