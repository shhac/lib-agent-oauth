package oauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"strings"
)

// pairingCodeStoreKey is where the pairing code lives in the SecretStore.
const pairingCodeStoreKey = "pairing-code"

// pairingPrefix identifies the code in logs and paste boxes (the modern secret
// convention, like sk- / ghp_).
const pairingPrefix = "mcp-"

// crockford is Crockford's base32 alphabet — no I/L/O/U, so the code is
// legible and resistant to transcription mistakes. The encoder is padding-free.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var crockEnc = base32.NewEncoding(crockford).WithPadding(base32.NoPadding)

// Pairing manages the pairing codes humans enter at the authorize endpoint:
// the shared operator code (reusable, so every client can pair with it) plus
// the named-principal codes (see principal.go).
type Pairing struct {
	store SecretStore
	// principals is held as a field — like clientRegistry and refreshStore —
	// so its mutex actually serializes concurrent principal mutations.
	principals *jsonMapStore[principalRecord]
}

// NewPairing returns a Pairing backed by store.
func NewPairing(store SecretStore) *Pairing {
	return &Pairing{
		store:      store,
		principals: &jsonMapStore[principalRecord]{store: store, key: principalsStoreKey},
	}
}

// Code returns the pairing code, generating and persisting one on first use so
// it is stable across restarts.
func (p *Pairing) Code() (string, error) {
	if v, ok, err := p.store.Get(pairingCodeStoreKey); err != nil {
		return "", err
	} else if ok {
		return v, nil
	}
	return p.Rotate()
}

// Rotate generates a fresh pairing code, stores it, and returns it. Any code a
// client paired with before is invalidated.
func (p *Pairing) Rotate() (string, error) {
	code, err := generatePairingCode()
	if err != nil {
		return "", err
	}
	if err := p.store.Set(pairingCodeStoreKey, code); err != nil {
		return "", err
	}
	return code, nil
}

// generatePairingCode returns a prefixed, hyphen-grouped, ~125-bit Crockford
// base32 code, e.g. "mcp-K7Q29-F3MXR-8WZ4T-...".
func generatePairingCode() (string, error) {
	b := make([]byte, 16) // 128 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: generating pairing code: %w", err)
	}
	s := crockEnc.EncodeToString(b)[:25] // 25 chars → five 5-char groups
	groups := make([]string, 0, 5)
	for i := 0; i < len(s); i += 5 {
		groups = append(groups, s[i:i+5])
	}
	return pairingPrefix + strings.Join(groups, "-"), nil
}

// constantTimeEqualPairing compares an already-normalized input against a
// stored code (normalized here), in constant time.
func constantTimeEqualPairing(normalizedInput, storedCode string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(normalizedInput), []byte(normalizePairing(storedCode))) == 1
}

// normalizePairing canonicalizes a code for comparison: lowercase, strip
// hyphens/spaces, drop the prefix, and fold the Crockford-confusable characters.
// Order matters — separators are removed before the prefix, so a de-hyphenated
// "mcpXXXXX…" still has its prefix recognised.
func normalizePairing(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("-", "", " ", "").Replace(s)
	s = strings.TrimPrefix(s, strings.ReplaceAll(pairingPrefix, "-", ""))
	s = strings.NewReplacer("o", "0", "i", "1", "l", "1").Replace(s)
	return strings.ToUpper(s)
}
