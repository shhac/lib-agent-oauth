package oauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

// maxRegisterBody caps the DCR request body.
const maxRegisterBody = 64 << 10

// handleRegister implements RFC 7591 Dynamic Client Registration: a client posts
// its redirect URIs (and optional name) and gets a client_id. Clients are public
// (PKCE, no secret), so no client_secret is issued.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRegisterBody)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body is not valid JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri",
				"redirect_uri must be absolute https, or http on a loopback host")
			return
		}
	}

	c, err := s.clients.Register(req.RedirectURIs, req.ClientName)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not register client")
		return
	}
	s.event(Event{Type: EventClientRegistered, Client: c.Name})
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  c.ID,
		"redirect_uris":              c.RedirectURIs,
		"client_name":                c.Name,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
}

// validRedirectURI accepts an absolute https URL, or http on a loopback host (the
// pattern native clients use for their local callback).
func validRedirectURI(s string) bool {
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	default:
		return false
	}
}

// methodNotAllowed is the shared 405 for the POST-only endpoints.
func methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", http.MethodPost)
	writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
}
