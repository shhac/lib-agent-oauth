package oauth

import "net/http"

// handleProtectedResourceMetadata serves the RFC 9728 Protected Resource
// Metadata: it tells a client this resource's authorization server (us) and the
// scopes it understands, so a 401 can bootstrap discovery.
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.publicURL},
		"scopes_supported":         s.scopes,
		"bearer_methods_supported": []string{"header"},
	})
}

// handleAuthServerMetadata serves the RFC 8414 Authorization Server Metadata:
// the endpoint URLs and the capabilities a client needs to register and run the
// PKCE authorization-code flow. issuer is the public URL root (so the .well-known
// paths stay clean).
func (s *Server) handleAuthServerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.publicURL,
		"authorization_endpoint":                s.publicURL + AuthorizePath,
		"token_endpoint":                        s.publicURL + TokenPath,
		"registration_endpoint":                 s.publicURL + RegisterPath,
		"scopes_supported":                      s.scopes,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{pkceMethodS256},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}
