package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// randToken returns nbytes of cryptographic randomness as a URL-safe,
// unpadded base64 string — used for opaque ids (client ids, auth codes,
// refresh tokens) the agent only echoes back, never reads.
func randToken(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: reading randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
