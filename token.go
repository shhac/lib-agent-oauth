package oauth

import (
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

// signingKeyBytes is the HMAC key length. A shorter key (e.g. a truncated or
// empty store entry) is rejected at load — HS256 would otherwise sign and
// self-validate with a weak/empty key, yielding trivially forgeable tokens.
const signingKeyBytes = 32

// signingMethod is the only algorithm the issuer mints and accepts. Pinning it
// (with WithValidMethods on parse) closes the "alg" confusion / "none" attacks.
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

// Issuer mints and validates the layer's own access tokens (stateless JWTs), so
// the Resource Server validates per-token with no shared session — which is what
// lets many clients hold valid tokens at once. issuer and audience are both the
// server's public URL in local mode; tokens are bound to that audience so they
// can't be replayed at another server (RFC 8707).
type Issuer struct {
	key      []byte
	issuer   string
	audience string
	ttl      time.Duration
}

// NewIssuer loads (or generates and persists) the signing key from store and
// returns an Issuer that mints audience-bound tokens valid for ttl.
func NewIssuer(store SecretStore, issuer, audience string, ttl time.Duration) (*Issuer, error) {
	key, err := loadOrCreateKey(store)
	if err != nil {
		return nil, err
	}
	return &Issuer{key: key, issuer: issuer, audience: audience, ttl: ttl}, nil
}

// Mint returns a signed access token for clientID with scope and the pairing
// principal p, plus its lifetime.
func (i *Issuer) Mint(clientID, scope string, p PrincipalGrant) (token string, ttl time.Duration, err error) {
	now := time.Now()
	claims := tokenClaims{
		Scope:     scope,
		Principal: p.Name,
		Binding:   p.Binding,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   clientID,
			Audience:  jwt.ClaimStrings{i.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
		},
	}
	signed, err := jwt.NewWithClaims(signingMethod, claims).SignedString(i.key)
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
		func(*jwt.Token) (any, error) { return i.key, nil },
		jwt.WithValidMethods([]string{signingMethod.Alg()}),
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

// loadOrCreateKey returns the persisted 32-byte signing key, generating and
// storing one (base64url) on first use.
func loadOrCreateKey(store SecretStore) ([]byte, error) {
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
