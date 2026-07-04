package oauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	hostURL      = "https://hub.example"
	slackAud     = "https://hub.example/slack/mcp"
	rsTestClient = "client-xyz"
)

// edIssuer builds an EdDSA host issuer over a fresh MemStore for the given
// audience, plus a delegate ResourceServer verifying its tokens for that
// resource.
func edIssuer(t *testing.T, audience string) (*Issuer, *ResourceServer) {
	t.Helper()
	iss, err := NewEd25519Issuer(NewMemStore(), hostURL, audience, time.Hour)
	if err != nil {
		t.Fatalf("NewEd25519Issuer: %v", err)
	}
	rs, err := NewResourceServer(RSConfig{IssuerURL: hostURL, Resource: audience, VerifyKey: iss.PublicKey()})
	if err != nil {
		t.Fatalf("NewResourceServer: %v", err)
	}
	return iss, rs
}

// The whole point: the host mints with its private key, the delegate verifies
// with only the public key, and the carried principal survives the round-trip.
func TestEd25519HostMintsDelegateVerifies(t *testing.T) {
	iss, rs := edIssuer(t, slackAud)

	tok, _, err := iss.Mint(rsTestClient, "mcp", PrincipalGrant{Name: "alice", Binding: map[string]string{"workspace": "acme"}})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	v, err := rs.verifier.Validate(tok)
	if err != nil {
		t.Fatalf("delegate Validate: %v", err)
	}
	if v.Name != "alice" || v.Binding["workspace"] != "acme" || v.ClientID != rsTestClient {
		t.Errorf("verified = %+v", v)
	}
}

// A verify-only issuer (what a delegate holds) must never be able to mint.
func TestVerifierCannotMint(t *testing.T) {
	iss, _ := edIssuer(t, slackAud)
	verifier, err := NewEd25519Verifier(hostURL, slackAud, iss.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifier.Mint("c", "mcp", PrincipalGrant{}); err == nil {
		t.Error("verify-only issuer minted a token")
	}
}

// A token from a different host key must be rejected — the public key is the
// whole trust anchor.
func TestDelegateRejectsWrongKey(t *testing.T) {
	iss, _ := edIssuer(t, slackAud)
	// Build an RS trusting a DIFFERENT key than iss signs with.
	pub, _, _ := ed25519.GenerateKey(strings.NewReader(strings.Repeat("k", 64)))
	rs, err := NewResourceServer(RSConfig{IssuerURL: hostURL, Resource: slackAud, VerifyKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	tok, _, _ := iss.Mint("c", "mcp", PrincipalGrant{})
	if _, err := rs.verifier.Validate(tok); err == nil {
		t.Error("delegate accepted a token signed by an untrusted key")
	}
}

// A token for another tool's audience must not validate at this mount — a
// Slack token is useless at /lin/mcp.
func TestDelegateRejectsWrongAudience(t *testing.T) {
	slackIss, _ := edIssuer(t, slackAud)
	// A delegate for the lin mount, trusting the same host key.
	linRS, err := NewResourceServer(RSConfig{
		IssuerURL: hostURL, Resource: "https://hub.example/lin/mcp", VerifyKey: slackIss.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	slackTok, _, _ := slackIss.Mint("c", "mcp", PrincipalGrant{})
	if _, err := linRS.verifier.Validate(slackTok); err == nil {
		t.Error("a token for the slack audience validated at the lin mount")
	}
}

// Protect: no token → 401 challenge at the host's PRM; valid token → next runs
// with the principal on context.
func TestResourceServerProtect(t *testing.T) {
	iss, rs := edIssuer(t, slackAud)
	var seen *Verified
	h := rs.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := PrincipalFrom(r.Context()); ok {
			seen = &v
		}
		_, _ = io.WriteString(w, "ok")
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	// No token → 401 with a challenge pointing at the host's suffixed PRM.
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", resp.StatusCode)
	}
	wantPRM := hostURL + ProtectedResourceMetadataPath + "/slack/mcp"
	if wa := resp.Header.Get("WWW-Authenticate"); !strings.Contains(wa, wantPRM) {
		t.Errorf("challenge = %q, want resource_metadata %q", wa, wantPRM)
	}

	// Valid host token → 200, principal attached.
	tok, _, _ := iss.Mint("c", "mcp", PrincipalGrant{Name: "bob"})
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("valid-token status = %d, want 200", resp2.StatusCode)
	}
	if seen == nil || seen.Name != "bob" {
		t.Errorf("principal on context = %+v", seen)
	}
}

func TestNewResourceServerValidatesConfig(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	cases := map[string]RSConfig{
		"no issuer":               {Resource: slackAud, VerifyKey: pub},
		"no resource":             {IssuerURL: hostURL, VerifyKey: pub},
		"resource not under host": {IssuerURL: hostURL, Resource: "https://other.example/mcp", VerifyKey: pub},
		"bad key":                 {IssuerURL: hostURL, Resource: slackAud, VerifyKey: ed25519.PublicKey("short")},
	}
	for name, cfg := range cases {
		if _, err := NewResourceServer(cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := NewResourceServer(RSConfig{IssuerURL: hostURL, Resource: slackAud, VerifyKey: pub}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

// The EdDSA signing key survives a restart: a second issuer over the same
// store loads the persisted seed, yielding the same public key — so tokens
// minted before a restart still validate after it. The multi-tool host path.
func TestEd25519KeyPersistsAcrossIssuers(t *testing.T) {
	store := NewMemStore()
	first, err := NewEd25519Issuer(store, hostURL, slackAud, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewEd25519Issuer(store, hostURL, slackAud, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !first.PublicKey().Equal(second.PublicKey()) {
		t.Fatal("reloaded issuer has a different public key — the seed did not round-trip")
	}
	// A delegate built from the first key validates a token minted by the second.
	rs, err := NewResourceServer(RSConfig{IssuerURL: hostURL, Resource: slackAud, VerifyKey: first.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	tok, _, _ := second.Mint("c", "mcp", PrincipalGrant{Name: "alice"})
	if _, err := rs.verifier.Validate(tok); err != nil {
		t.Errorf("token from the reloaded key rejected: %v", err)
	}
}

// A corrupted stored Ed25519 seed must be rejected with an error, never a
// panic (ed25519.NewKeyFromSeed panics on a wrong-length seed) — the guard
// requires exactly SeedSize, so both too-short and too-long must fail.
func TestEd25519RejectsMalformedStoredSeed(t *testing.T) {
	cases := map[string]string{
		"non-base64": "!!!not base64!!!",
		"empty":      "",
		"too short":  base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SeedSize-1)),
		"too long":   base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SeedSize+1)),
	}
	for name, seed := range cases {
		t.Run(name, func(t *testing.T) {
			store := NewMemStore()
			if err := store.Set(ed25519SeedStoreKey, seed); err != nil {
				t.Fatal(err)
			}
			// Must return an error, and must not panic.
			if _, err := NewEd25519Issuer(store, hostURL, slackAud, time.Hour); err == nil {
				t.Error("malformed stored seed accepted")
			}
		})
	}
}

// Key confusion is the attack the delegate design invites: the host's public
// key is handed to every tool, so an attacker who knows it could forge an
// HS256 token using those public bytes as the HMAC secret. The EdDSA verifier
// pins "EdDSA" via WithValidMethods and must reject both that forgery and an
// alg=none token — the sole defense, verified here to fail closed.
func TestEd25519VerifierRejectsAlgConfusion(t *testing.T) {
	iss, rs := edIssuer(t, slackAud)
	claims := tokenClaims{
		Scope:     "mcp",
		Principal: "attacker",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    hostURL,
			Subject:   "c",
			Audience:  jwt.ClaimStrings{slackAud},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	// (a) HS256 forgery using the distributed public key as the HMAC secret.
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(iss.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rs.verifier.Validate(forged); err == nil {
		t.Error("EdDSA verifier accepted an HS256 token signed with its public key — key-confusion forgery succeeded")
	}

	// (b) alg=none token with otherwise-valid claims.
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rs.verifier.Validate(none); err == nil {
		t.Error("EdDSA verifier accepted an alg=none token")
	}
}

// The existing HS256 local path is unchanged: NewIssuer round-trips and its
// PublicKey is nil (symmetric).
func TestHS256IssuerUnchanged(t *testing.T) {
	iss, err := NewIssuer(NewMemStore(), "https://x", "https://x/mcp", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if iss.PublicKey() != nil {
		t.Error("HS256 issuer should have no Ed25519 public key")
	}
	tok, _, err := iss.Mint("c", "mcp", PrincipalGrant{Name: "z"})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := iss.Validate(tok); err != nil || v.Name != "z" {
		t.Errorf("HS256 round-trip: v=%+v err=%v", v, err)
	}
}
