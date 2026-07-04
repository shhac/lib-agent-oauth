package oauth

import (
	"sync"
	"time"
)

// authGrant is the state an authorization code stands in for between the
// authorize and token steps. It binds the code to the client, the redirect URI,
// the PKCE challenge, and the requested scope, so the token request must present
// a matching client/redirect and a verifier for the same challenge.
type authGrant struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	// Resource is the audience the eventual token is bound to (RFC 8707) — the
	// specific /mcp mount the client is authorizing for. Empty means the
	// server's default (single-resource) audience.
	Resource  string
	Principal PrincipalGrant

	expiresAt time.Time
}

// authCodeStore issues and consumes single-use authorization codes. Codes live
// only seconds (between authorize and token), so they are kept in memory.
type authCodeStore struct {
	mu  sync.Mutex
	m   map[string]authGrant
	ttl time.Duration
}

func newAuthCodeStore(ttl time.Duration) *authCodeStore {
	return &authCodeStore{m: map[string]authGrant{}, ttl: ttl}
}

// issue stores grant under a fresh random code and returns the code.
func (s *authCodeStore) issue(grant authGrant) (string, error) {
	code, err := randToken(32)
	if err != nil {
		return "", err
	}
	grant.expiresAt = time.Now().Add(s.ttl)
	s.mu.Lock()
	s.m[code] = grant
	s.mu.Unlock()
	return code, nil
}

// consume returns the grant for code and removes it (single-use), reporting
// false if the code is unknown or expired.
func (s *authCodeStore) consume(code string) (authGrant, bool) {
	s.mu.Lock()
	grant, ok := s.m[code]
	delete(s.m, code) // single-use: gone whether or not it's still valid
	s.mu.Unlock()
	if !ok || time.Now().After(grant.expiresAt) {
		return authGrant{}, false
	}
	return grant, true
}
