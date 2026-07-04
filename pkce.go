package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// pkceMethodS256 is the only PKCE transform we accept. OAuth 2.1 requires PKCE
// and S256; "plain" is refused so a challenge can't be replayed as a verifier.
const pkceMethodS256 = "S256"

// verifyPKCE reports whether verifier matches challenge under the S256 method:
// base64url(sha256(verifier)) == challenge, compared in constant time. Any other
// method (including "plain" or empty) fails.
func verifyPKCE(challenge, method, verifier string) bool {
	if method != pkceMethodS256 || challenge == "" || verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
