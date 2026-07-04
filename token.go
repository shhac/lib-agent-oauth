package oauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signingKeyStoreKey is where the HMAC token-signing key lives in the
// SecretStore. It is generated once and reused, so tokens survive a restart.
const signingKeyStoreKey = "signing-key"

// ed25519SeedStoreKey is where the EdDSA signing key's 32-byte seed lives — a
// separate slot from the HMAC key so the two algorithms never collide in one
// store. Only an asymmetric issuer (the multi-tool host) uses it.
const ed25519SeedStoreKey = "ed25519-seed"

// signingKeyBytes is the HMAC key length. A shorter key (e.g. a truncated or
// empty store entry) is rejected at load — HS256 would otherwise sign and
// self-validate with a weak/empty key, yielding trivially forgeable tokens.
const signingKeyBytes = 32

// signingMethod is the symmetric algorithm the default (single-tool) issuer
// mints and accepts. Pinning it (with WithValidMethods on parse) closes the
// "alg" confusion / "none" attacks. Asymmetric issuers pin EdDSA instead.
var signingMethod = jwt.SigningMethodHS256

// tokenClaims is the JWT body: the registered claims plus an OAuth scope and
// the pairing-established principal identity (name + binding). Both ride in
// the signed token, so the Resource Server needs no per-call store lookup and
// the values are tamper-proof.
type tokenClaims struct {
	Scope     string            `json:"scope,omitempty"`
	Principal string            `json:"principal,omitempty"`
	Binding   map[string]string `json:"binding,omitempty"`
	jwt.RegisteredClaims
}

// Verified is the validated identity carried by an access token. Protect
// attaches it to the request context (see PrincipalFrom), which is how tool
// dispatch learns which principal a call acts for.
type Verified struct {
	ClientID string
	Scope    string
	// PrincipalGrant is the named pairing identity the token was approved
	// under (zero for the anonymous operator / shared code): Name, plus the
	// Binding that WithIdentityBinding translates into subprocess argv/env.
	PrincipalGrant
	ExpiresAt time.Time
}

// Issuer mints and/or validates the layer's access tokens (stateless JWTs), so
// the Resource Server validates per-token with no shared session — which is
// what lets many clients hold valid tokens at once. Tokens are audience-bound
// so they can't be replayed at another resource (RFC 8707).
//
// Three shapes, by constructor:
//   - NewIssuer:          HS256 symmetric — one server signs and self-validates
//     (single-tool `--oauth local`). signKey == verifyKey.
//   - NewEd25519Issuer:   EdDSA — the multi-tool host signs; delegate tools
//     verify. Holds the private key (can Mint) and the public key.
//   - NewEd25519Verifier: EdDSA, verify-only — a delegate tool holds just the
//     host's public key. signKey is nil, so Mint refuses.
type Issuer struct {
	method    jwt.SigningMethod
	signKey   any // nil ⇒ verify-only (cannot Mint)
	verifyKey any
	issuer    string
	audience  string
	ttl       time.Duration
}

// NewIssuer loads (or generates and persists) the HMAC signing key from store
// and returns an HS256 issuer that mints audience-bound tokens valid for ttl.
func NewIssuer(store SecretStore, issuer, audience string, ttl time.Duration) (*Issuer, error) {
	key, err := loadOrCreateHMACKey(store)
	if err != nil {
		return nil, err
	}
	return &Issuer{method: signingMethod, signKey: key, verifyKey: key, issuer: issuer, audience: audience, ttl: ttl}, nil
}

// NewEd25519Issuer loads (or generates and persists) an Ed25519 keypair from
// store and returns an EdDSA issuer that mints audience-bound tokens valid for
// ttl. The host uses this so its public key can hand token verification to
// delegate tools while the private key never leaves it.
func NewEd25519Issuer(store SecretStore, issuer, audience string, ttl time.Duration) (*Issuer, error) {
	priv, err := loadOrCreateEd25519(store)
	if err != nil {
		return nil, err
	}
	return &Issuer{
		method:    jwt.SigningMethodEdDSA,
		signKey:   priv,
		verifyKey: priv.Public().(ed25519.PublicKey),
		issuer:    issuer,
		audience:  audience,
		ttl:       ttl,
	}, nil
}

// NewEd25519Verifier returns a verify-only EdDSA issuer that validates tokens
// minted by a host holding the matching private key. A delegate tool
// (`--oauth <host-url>`) uses this: it can check who a caller is but can never
// mint a token itself.
func NewEd25519Verifier(issuer, audience string, pub ed25519.PublicKey) (*Issuer, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("oauth: Ed25519 public key is %d bytes, need %d", len(pub), ed25519.PublicKeySize)
	}
	return &Issuer{method: jwt.SigningMethodEdDSA, signKey: nil, verifyKey: pub, issuer: issuer, audience: audience}, nil
}

// PublicKey returns the issuer's Ed25519 public key, or nil for a symmetric
// (HS256) issuer. The host hands this to each delegate tool at spawn.
func (i *Issuer) PublicKey() ed25519.PublicKey {
	if pub, ok := i.verifyKey.(ed25519.PublicKey); ok {
		return pub
	}
	return nil
}

// Mint returns a signed access token bound to the issuer's own audience — the
// single-resource case. It errors on a verify-only issuer.
func (i *Issuer) Mint(clientID, scope string, p PrincipalGrant) (token string, ttl time.Duration, err error) {
	return i.MintFor(clientID, scope, i.audience, p)
}

// MintFor returns a signed access token bound to a specific audience, for a
// multi-audience Authorization Server (the host) that mints per-mount tokens
// from one signing key. The audience must be one the AS is allowed to issue
// for — validation is the caller's responsibility (see Server.resolveResource).
func (i *Issuer) MintFor(clientID, scope, audience string, p PrincipalGrant) (token string, ttl time.Duration, err error) {
	if i.signKey == nil {
		return "", 0, errors.New("oauth: verify-only issuer cannot mint tokens")
	}
	now := time.Now()
	claims := tokenClaims{
		Scope:     scope,
		Principal: p.Name,
		Binding:   p.Binding,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   clientID,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
		},
	}
	signed, err := jwt.NewWithClaims(i.method, claims).SignedString(i.signKey)
	if err != nil {
		return "", 0, fmt.Errorf("oauth: signing token: %w", err)
	}
	return signed, i.ttl, nil
}

// Validate verifies a bearer token: signature (with the pinned method), issuer,
// audience, and a required, unexpired exp. It returns the carried identity.
func (i *Issuer) Validate(token string) (*Verified, error) {
	var claims tokenClaims
	parsed, err := jwt.ParseWithClaims(token, &claims,
		func(*jwt.Token) (any, error) { return i.verifyKey, nil },
		jwt.WithValidMethods([]string{i.method.Alg()}),
		jwt.WithIssuer(i.issuer),
		jwt.WithAudience(i.audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	if !parsed.Valid || claims.ExpiresAt == nil {
		return nil, errors.New("oauth: invalid token")
	}
	return &Verified{
		ClientID:       claims.Subject,
		Scope:          claims.Scope,
		PrincipalGrant: PrincipalGrant{Name: claims.Principal, Binding: claims.Binding},
		ExpiresAt:      claims.ExpiresAt.Time,
	}, nil
}

// loadOrCreateHMACKey returns the persisted 32-byte HMAC signing key,
// generating and storing one (base64url) on first use.
func loadOrCreateHMACKey(store SecretStore) ([]byte, error) {
	v, ok, err := store.Get(signingKeyStoreKey)
	if err != nil {
		return nil, err
	}
	if ok {
		key, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("oauth: decoding stored signing key: %w", err)
		}
		if len(key) < signingKeyBytes {
			return nil, fmt.Errorf("oauth: stored signing key is %d bytes, need >= %d — refusing to sign with a weak key", len(key), signingKeyBytes)
		}
		return key, nil
	}
	key := make([]byte, signingKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("oauth: generating signing key: %w", err)
	}
	if err := store.Set(signingKeyStoreKey, base64.RawURLEncoding.EncodeToString(key)); err != nil {
		return nil, err
	}
	return key, nil
}

// loadOrCreateEd25519 returns the persisted Ed25519 private key, generating and
// storing its 32-byte seed (base64url) on first use.
func loadOrCreateEd25519(store SecretStore) (ed25519.PrivateKey, error) {
	v, ok, err := store.Get(ed25519SeedStoreKey)
	if err != nil {
		return nil, err
	}
	if ok {
		seed, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("oauth: decoding stored Ed25519 seed: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("oauth: stored Ed25519 seed is %d bytes, need %d — refusing a malformed key", len(seed), ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("oauth: generating Ed25519 key: %w", err)
	}
	if err := store.Set(ed25519SeedStoreKey, base64.RawURLEncoding.EncodeToString(priv.Seed())); err != nil {
		return nil, err
	}
	return priv, nil
}
