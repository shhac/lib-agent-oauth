package oauth

import (
	"net/url"
	"strings"
	"testing"
)

// failStore wraps a working store but can be flipped to return ErrStoreUnavailable
// from every operation — so a test can let setup succeed, then simulate the
// keyring going degraded mid-flow and assert the handlers fail closed.
type failStore struct {
	inner *MemStore
	fail  bool
}

func (f *failStore) Get(k string) (string, bool, error) {
	if f.fail {
		return "", false, ErrStoreUnavailable
	}
	return f.inner.Get(k)
}

func (f *failStore) Set(k, v string) error {
	if f.fail {
		return ErrStoreUnavailable
	}
	return f.inner.Set(k, v)
}

func (f *failStore) Delete(k string) error {
	if f.fail {
		return ErrStoreUnavailable
	}
	return f.inner.Delete(k)
}

// TestHandlersFailClosedOnDegradedStore asserts the OAuth endpoints return a clean
// 5xx (not a panic or a partial/empty 200) when the secret store fails after
// startup — e.g. the keyring becomes unavailable while the server is running.
func TestHandlersFailClosedOnDegradedStore(t *testing.T) {
	store := &failStore{inner: NewMemStore()}
	h := newHarnessWithStore(t, store)

	// Complete a normal flow while the store works, to obtain a refresh token.
	pairing, _ := h.srv.PairingCode()
	clientID := h.registerClient(t)
	code := h.authorize(t, clientID, pairing).Query().Get("code")
	refresh, _ := h.exchange(t, clientID, code)["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("setup did not yield a refresh token")
	}

	store.fail = true // the keyring goes degraded

	t.Run("refresh exchange fails closed", func(t *testing.T) {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}}
		resp := h.postForm(t, TokenPath, form)
		defer resp.Body.Close()
		if resp.StatusCode < 500 {
			t.Errorf("refresh with a degraded store = %d, want 5xx", resp.StatusCode)
		}
	})

	t.Run("dynamic client registration fails closed", func(t *testing.T) {
		resp, err := h.client.Post(h.url(RegisterPath), "application/json",
			strings.NewReader(`{"redirect_uris":["`+testRedirect+`"]}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 500 {
			t.Errorf("DCR with a degraded store = %d, want 5xx", resp.StatusCode)
		}
	})
}
