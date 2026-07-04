package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestVerifyPKCE(t *testing.T) {
	verifier := "a-high-entropy-code-verifier-string-1234567890"
	challenge := challengeFor(verifier)

	if !verifyPKCE(challenge, "S256", verifier) {
		t.Error("valid S256 verifier rejected")
	}
	if verifyPKCE(challenge, "S256", "wrong-verifier") {
		t.Error("wrong verifier accepted")
	}
	if verifyPKCE(verifier, "plain", verifier) {
		t.Error("plain method must be refused (OAuth 2.1)")
	}
	if verifyPKCE("", "S256", verifier) || verifyPKCE(challenge, "S256", "") {
		t.Error("empty challenge/verifier accepted")
	}
}

func TestAuthCodeSingleUseAndBinding(t *testing.T) {
	s := newAuthCodeStore(time.Minute)
	grant := authGrant{ClientID: "c1", RedirectURI: "https://cb", CodeChallenge: "ch", CodeChallengeMethod: "S256", Scope: "mcp"}

	code, err := s.issue(grant)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, ok := s.consume(code)
	if !ok {
		t.Fatal("first consume failed")
	}
	if got.ClientID != "c1" || got.RedirectURI != "https://cb" || got.CodeChallenge != "ch" || got.Scope != "mcp" {
		t.Errorf("grant not preserved: %+v", got)
	}
	if _, ok := s.consume(code); ok {
		t.Error("code consumed twice (must be single-use)")
	}
	if _, ok := s.consume("never-issued"); ok {
		t.Error("unknown code consumed")
	}
}

func TestAuthCodeExpiry(t *testing.T) {
	s := newAuthCodeStore(-time.Second) // issue already-expired
	code, _ := s.issue(authGrant{ClientID: "c"})
	if _, ok := s.consume(code); ok {
		t.Error("expired code accepted")
	}
}

func TestClientRegistryRoundTrip(t *testing.T) {
	r := newClientRegistry(NewMemStore())

	c, err := r.Register([]string{"https://claude/cb"}, "Claude")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if c.ID == "" {
		t.Fatal("empty client id")
	}
	got, ok, err := r.Get(c.ID)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.Name != "Claude" || !got.allowsRedirect("https://claude/cb") || got.allowsRedirect("https://evil/cb") {
		t.Errorf("client not preserved / redirect check wrong: %+v", got)
	}

	// A second registration persists alongside the first.
	c2, _ := r.Register([]string{"https://codex/cb"}, "Codex")
	if _, ok, _ := r.Get(c.ID); !ok {
		t.Error("first client lost after second registration")
	}
	if _, ok, _ := r.Get(c2.ID); !ok {
		t.Error("second client not stored")
	}
	if _, ok, _ := r.Get("unknown"); ok {
		t.Error("unknown client id returned ok")
	}
}
