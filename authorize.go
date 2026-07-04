package oauth

import (
	"net/http"
	"net/url"
)

// handleAuthorize renders the approval form (GET) and processes it (POST).
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.authorizeForm(w, r, parseAuthParams(r.URL.Query()))
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.authorizeErrorPage(w, "could not parse the form")
			return
		}
		s.authorizeSubmit(w, r, parseAuthParams(r.PostForm))
	default:
		w.Header().Set("Allow", "GET, POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
	}
}

// validatedRequest runs the shared authorization-request safety gates: it
// resolves and checks the client/redirect (fatal → error page) and the
// redirectable request params (→ error redirect). Both the GET form and the
// POST submission go through it, so the gates can't drift between them. A false
// second return means a response was already written.
func (s *Server) validatedRequest(w http.ResponseWriter, r *http.Request, p authParams) (Client, bool) {
	client, fatal := s.validateClientRedirect(p)
	if fatal != "" {
		s.authorizeErrorPage(w, fatal)
		return Client{}, false
	}
	if errCode := validateAuthParams(p); errCode != "" {
		s.redirectError(w, r, p, errCode)
		return Client{}, false
	}
	// RFC 8707: the requested resource (token audience) must be one this server
	// is allowed to issue for. A bad target is a redirectable error.
	if _, ok := s.resolveResource(p.resource); !ok {
		s.redirectError(w, r, p, "invalid_target")
		return Client{}, false
	}
	return client, true
}

// authorizeForm validates the request, then shows the pairing-code form.
func (s *Server) authorizeForm(w http.ResponseWriter, r *http.Request, p authParams) {
	client, ok := s.validatedRequest(w, r, p)
	if !ok {
		return
	}
	s.renderForm(w, client, p, "")
}

// authorizeSubmit re-validates, checks the pairing code, then — for a named
// principal with enrollment configured — may divert into the enrollment page
// before the usual authorization-code issue + redirect.
func (s *Server) authorizeSubmit(w http.ResponseWriter, r *http.Request, p authParams) {
	client, valid := s.validatedRequest(w, r, p)
	if !valid {
		return
	}

	principal, ok, err := s.pairing.VerifyPrincipal(r.PostForm.Get("pairing_code"))
	if err != nil {
		s.authorizeErrorPage(w, "internal error verifying the pairing code")
		return
	}
	if !ok {
		s.renderForm(w, client, p, "Incorrect pairing code — try again.")
		return
	}

	if s.divertToEnrollment(w, r, client, p, principal) {
		return
	}

	principal, handled := s.resolveSetBindings(w, r, client, p, principal)
	if handled {
		return
	}

	s.issueAndRedirect(w, r, client, p, principal)
}

// divertToEnrollment handles the enrollment gate for a named principal: an
// enrollment POST is dispatched, and an unbound (or explicitly re-enrolling)
// principal is shown the enrollment form. It reports whether it wrote a
// response, in which case the caller returns. Enrollment applies only to named
// principals — the anonymous operator acts with the CLI's own credentials and
// has no binding to write.
func (s *Server) divertToEnrollment(w http.ResponseWriter, r *http.Request, client Client, p authParams, principal PrincipalGrant) bool {
	e := s.enrollmentFor(p)
	if e == nil || principal.Name == "" {
		return false
	}
	if r.PostForm.Get("enroll") == "1" {
		s.enrollSubmit(w, r, client, p, principal, e)
		return true
	}
	// Unbound means unbound FOR THIS RESOURCE: in host mode a principal with
	// only another tool's namespaced keys projects to empty here and still
	// needs to enroll for this one.
	if len(s.projectedBinding(principal.Binding, p)) == 0 || r.PostForm.Get("update_credentials") != "" {
		s.renderEnrollPage(w, client, p, r.PostForm.Get("pairing_code"), principal, enrollView{}, e)
		return true
	}
	return false
}

// resolveSetBindings handles allowed-set bindings: a set-valued binding needs
// the person to pick one member per key before a token can carry a singleton.
// Choices are validated against the STORED binding, so a forged POST cannot
// select an unoffered value. It returns the grant to issue — resolved to
// singletons when a valid choice was made — and whether it wrote a response
// (the chooser page or a re-prompt), in which case the caller returns.
func (s *Server) resolveSetBindings(w http.ResponseWriter, r *http.Request, client Client, p authParams, principal PrincipalGrant) (PrincipalGrant, bool) {
	if principal.Name == "" || len(setValuedKeys(principal.Binding)) == 0 {
		return principal, false
	}
	pairingCode := r.PostForm.Get("pairing_code")
	if r.PostForm.Get("choose") != "1" {
		s.renderBindingChooser(w, client, p, pairingCode, principal, "")
		return principal, true
	}
	resolved, ok := resolveBindingChoices(principal.Binding, func(key string) string {
		return r.PostForm.Get("choice_" + key)
	})
	if !ok {
		s.renderBindingChooser(w, client, p, pairingCode, principal, "Pick one of the offered values.")
		return principal, true
	}
	return PrincipalGrant{Name: principal.Name, Binding: resolved}, false
}

// issueAndRedirect mints the single-use authorization code carrying the grant
// and sends the browser back to the client — the flow's terminal step, shared
// by the plain approval and the post-enrollment path.
func (s *Server) issueAndRedirect(w http.ResponseWriter, r *http.Request, client Client, p authParams, principal PrincipalGrant) {
	resource, _ := s.resolveResource(p.resource) // validated in validatedRequest
	code, err := s.codes.issue(authGrant{
		ClientID:            client.ID,
		RedirectURI:         p.redirectURI,
		CodeChallenge:       p.codeChallenge,
		CodeChallengeMethod: p.codeChallengeMethod,
		Scope:               s.grantedScope(p.scope),
		Resource:            resource,
		Principal:           principal,
	})
	if err != nil {
		s.authorizeErrorPage(w, "internal error issuing the authorization code")
		return
	}
	s.redirectWith(w, r, p, url.Values{"code": {code}})
}

// validateClientRedirect resolves the client and checks the redirect URI is one
// it registered. A non-empty string is a fatal error (no safe redirect target).
func (s *Server) validateClientRedirect(p authParams) (Client, string) {
	if p.clientID == "" {
		return Client{}, "missing client_id"
	}
	c, ok, err := s.clients.Get(p.clientID)
	if err != nil {
		return Client{}, "internal error looking up the client"
	}
	if !ok {
		return Client{}, "unknown client_id"
	}
	if p.redirectURI == "" || !c.allowsRedirect(p.redirectURI) {
		return Client{}, "redirect_uri is not registered for this client"
	}
	return c, ""
}

// validateAuthParams checks the redirectable request parameters; a non-empty
// return is an OAuth error code to send back to the client's redirect URI.
func validateAuthParams(p authParams) string {
	switch {
	case p.responseType != "code":
		return "unsupported_response_type"
	case p.codeChallenge == "" || p.codeChallengeMethod != pkceMethodS256:
		return "invalid_request"
	default:
		return ""
	}
}

// grantedScope returns the scope to bind to the code: the requested one if any,
// else the server's default.
func (s *Server) grantedScope(requested string) string {
	if requested != "" {
		return requested
	}
	return s.scopes[0]
}

// redirectError redirects to the client with an OAuth error and the state.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, p authParams, errCode string) {
	s.redirectWith(w, r, p, url.Values{"error": {errCode}})
}

// redirectWith redirects to p.redirectURI with extra query params plus state.
func (s *Server) redirectWith(w http.ResponseWriter, r *http.Request, p authParams, extra url.Values) {
	u, err := url.Parse(p.redirectURI)
	if err != nil {
		s.authorizeErrorPage(w, "invalid redirect_uri")
		return
	}
	q := u.Query()
	for k, vs := range extra {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	if p.state != "" {
		q.Set("state", p.state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
