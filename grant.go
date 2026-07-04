package oauth

import "net/http"

// handleToken is the token endpoint: it dispatches the supported grant types.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "could not parse the form")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.grantAuthCode(w, r)
	case "refresh_token":
		s.grantRefresh(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"supported: authorization_code, refresh_token")
	}
}

// grantAuthCode exchanges an authorization code + PKCE verifier for tokens.
func (s *Server) grantAuthCode(w http.ResponseWriter, r *http.Request) {
	grant, ok := s.codes.consume(r.PostForm.Get("code"))
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}
	if grant.ClientID != r.PostForm.Get("client_id") || grant.RedirectURI != r.PostForm.Get("redirect_uri") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id or redirect_uri does not match the code")
		return
	}
	if !verifyPKCE(grant.CodeChallenge, grant.CodeChallengeMethod, r.PostForm.Get("code_verifier")) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	s.issueTokens(w, grant.ClientID, grant.Scope, grant.Resource, grant.Principal)
}

// grantRefresh exchanges a (rotating) refresh token for fresh tokens.
func (s *Server) grantRefresh(w http.ResponseWriter, r *http.Request) {
	g, ok, err := s.refresh.exchange(r.PostForm.Get("refresh_token"))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not read refresh token")
		return
	}
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh_token is invalid")
		return
	}
	if cid := r.PostForm.Get("client_id"); cid != "" && cid != g.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id does not match the refresh token")
		return
	}
	s.issueTokens(w, g.ClientID, g.Scope, g.Resource, g.Principal)
}

// issueTokens mints an access token (+ a rotating refresh token) bound to the
// given resource audience, and writes the RFC 6749 token response. resource is
// always a concrete, pre-validated audience: both callers pass a stored grant's
// Resource, itself set from resolveResource (which resolves empty to the default
// before the grant is persisted).
func (s *Server) issueTokens(w http.ResponseWriter, clientID, scope, resource string, p PrincipalGrant) {
	// Project the stored binding into the vocabulary this resource's tool
	// understands (e.g. strip a "slack:" namespace) before it rides in the
	// access token. The refresh token stores the ORIGINAL principal (below), so
	// a refresh re-projects from scratch rather than re-projecting an
	// already-projected binding.
	tokenGrant := p
	if s.bindingForResource != nil {
		tokenGrant = PrincipalGrant{Name: p.Name, Binding: s.bindingForResource(p.Binding, resource)}
	}
	access, ttl, err := s.issuer.MintFor(clientID, scope, resource, tokenGrant)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue access token")
		return
	}
	refresh, err := s.refresh.issue(clientID, scope, resource, p)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue refresh token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(ttl.Seconds()),
		"refresh_token": refresh,
		"scope":         scope,
	})
}
