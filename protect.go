package oauth

import (
	"fmt"
	"net/http"
	"strings"
)

// protectHandler gates next behind a valid, validate-passing bearer token,
// attaching the carried identity to the request context; otherwise it answers
// the 401 discovery challenge pointing at prmURL. Shared by the local Server
// and a delegate ResourceServer so the gate can't drift between them.
func protectHandler(validate func(string) (*Verified, error), prmURL string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			challengeUnauthorized(w, prmURL, "missing bearer token")
			return
		}
		v, err := validate(token)
		if err != nil {
			challengeUnauthorized(w, prmURL, "invalid or expired token")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), *v)))
	})
}

// challengeUnauthorized writes the 401 + WWW-Authenticate that bootstraps
// discovery, pointing the client at prmURL for the protected-resource metadata.
func challengeUnauthorized(w http.ResponseWriter, prmURL, desc string) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf("Bearer resource_metadata=%q", prmURL))
	writeOAuthError(w, http.StatusUnauthorized, "invalid_token", desc)
}

// resourceSuffix is the path of resource under base — e.g. "/mcp" — or "" when
// resource is the bare host (or base itself). Used both to mount the suffixed
// metadata route and to build the metadata URL, so the two agree.
func resourceSuffix(base, resource string) string {
	if p := strings.TrimPrefix(resource, base); p != "/" {
		return p
	}
	return ""
}

// protectedResourceMetadataURL builds the RFC 9728 metadata URL for a resource
// under base: base + the well-known path + the resource's path suffix. It is
// the single source for this security-relevant URL, shared by the local Server
// and a delegate ResourceServer — the URL a delegate challenges toward is the
// exact one the host's Server must serve, so the two cannot drift.
func protectedResourceMetadataURL(base, resource string) string {
	return base + ProtectedResourceMetadataPath + resourceSuffix(base, resource)
}
