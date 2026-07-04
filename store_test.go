package oauth

import (
	"errors"
	"testing"

	keyring "github.com/shhac/lib-agent-keyring"
)

func TestMemStoreRoundTrip(t *testing.T) {
	s := NewMemStore()

	if _, ok, err := s.Get("k"); ok || err != nil {
		t.Fatalf("empty get = (_, %v, %v), want (_, false, nil)", ok, err)
	}
	if err := s.Set("k", "v"); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := s.Get("k"); !ok || err != nil || v != "v" {
		t.Errorf("get after set = (%q, %v, %v), want (v, true, nil)", v, ok, err)
	}
	if err := s.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get("k"); ok {
		t.Error("get after delete still present")
	}
	if err := s.Delete("absent"); err != nil {
		t.Errorf("delete of absent key errored: %v", err)
	}
}

func TestKeyringStoreUnavailableIsErr(t *testing.T) {
	// Force the keyring opt-out so the backend reports unavailable, exercising the
	// ErrStoreUnavailable path without touching a real OS secret store.
	t.Setenv(keyring.NoKeychainEnv, "1")

	s := NewKeyringStore("app.example.test.mcp")
	if s.Available() {
		t.Fatal("keyring should be unavailable when the opt-out env is set")
	}
	if err := s.Set("k", "v"); !errors.Is(err, ErrStoreUnavailable) {
		t.Errorf("Set = %v, want ErrStoreUnavailable", err)
	}
	if _, _, err := s.Get("k"); !errors.Is(err, ErrStoreUnavailable) {
		t.Errorf("Get = %v, want ErrStoreUnavailable", err)
	}
	if err := s.Delete("k"); !errors.Is(err, ErrStoreUnavailable) {
		t.Errorf("Delete = %v, want ErrStoreUnavailable", err)
	}
	// The `pair reset` wipe must also refuse to silently no-op on a degraded host.
	if err := s.DeleteAll(); !errors.Is(err, ErrStoreUnavailable) {
		t.Errorf("DeleteAll = %v, want ErrStoreUnavailable", err)
	}
}

// storeContract is satisfied by both implementations — a compile-time guard that
// they stay interface-compatible.
var (
	_ SecretStore = (*MemStore)(nil)
	_ SecretStore = (*KeyringStore)(nil)
)
