package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	testPublicURL  = "https://mcp.example.com"
	testRedirect   = "https://client.example/callback"
	testVerifier   = "a-sufficiently-long-pkce-code-verifier-0123456789"
	testToolOKBody = "tool-ok"
)

// oauthHarness builds a Server (MemStore) and an httptest.Server that mounts the
// OAuth routes and a Protect-gated /mcp.
type oauthHarness struct {
	srv    *Server
	http   *httptest.Server
	client *http.Client
}

func newHarness(t *testing.T) *oauthHarness {
	return newHarnessWithStore(t, NewMemStore())
}

func newHarnessWithStore(t *testing.T, store SecretStore) *oauthHarness {
	t.Helper()
	srv, err := New(Config{Store: store, PublicURL: testPublicURL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	mux.Handle("/mcp", srv.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(testToolOKBody))
	})))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	// Don't auto-follow redirects: we inspect the Location off the authorize POST.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &oauthHarness{srv: srv, http: ts, client: client}
}

func (h *oauthHarness) url(path string) string { return h.http.URL + path }

func (h *oauthHarness) get(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := h.client.Get(h.url(path))
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func (h *oauthHarness) postForm(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()
	resp, err := h.client.PostForm(h.url(path), form)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func (h *oauthHarness) getJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	resp, err := h.client.Get(h.url(path))
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return m
}

func TestMetadataDocuments(t *testing.T) {
	h := newHarness(t)

	prm := h.getJSON(t, ProtectedResourceMetadataPath)
	if prm["resource"] != testPublicURL {
		t.Errorf("PRM resource = %v, want %s", prm["resource"], testPublicURL)
	}
	if as, _ := prm["authorization_servers"].([]any); len(as) != 1 || as[0] != testPublicURL {
		t.Errorf("PRM authorization_servers = %v", prm["authorization_servers"])
	}

	md := h.getJSON(t, AuthServerMetadataPath)
	if md["issuer"] != testPublicURL {
		t.Errorf("AS issuer = %v", md["issuer"])
	}
	if md["authorization_endpoint"] != testPublicURL+AuthorizePath ||
		md["token_endpoint"] != testPublicURL+TokenPath ||
		md["registration_endpoint"] != testPublicURL+RegisterPath {
		t.Errorf("AS endpoints wrong: %v", md)
	}
	if m, _ := md["code_challenge_methods_supported"].([]any); len(m) != 1 || m[0] != "S256" {
		t.Errorf("AS pkce methods = %v, want [S256]", md["code_challenge_methods_supported"])
	}
}

func TestMCPRequiresToken(t *testing.T) {
	h := newHarness(t)
	resp, err := h.client.Get(h.url("/mcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	wa := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wa, "Bearer") || !strings.Contains(wa, ProtectedResourceMetadataPath) {
		t.Errorf("WWW-Authenticate = %q, want a Bearer resource_metadata challenge", wa)
	}
}

// A present-but-invalid bearer token is refused with the same discovery
// challenge as a missing one — Validate failing must not be treated leniently.
func TestMCPRejectsGarbageToken(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodGet, h.url("/mcp"), nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	wa := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wa, "Bearer") || !strings.Contains(wa, ProtectedResourceMetadataPath) {
		t.Errorf("WWW-Authenticate = %q, want a Bearer resource_metadata challenge", wa)
	}
}

// registerClient runs DCR and returns the client_id.
func (h *oauthHarness) registerClient(t *testing.T) string {
	t.Helper()
	body := `{"redirect_uris":["` + testRedirect + `"],"client_name":"Test Client"}`
	resp, err := h.client.Post(h.url(RegisterPath), "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want 201", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	id, _ := out["client_id"].(string)
	if id == "" {
		t.Fatal("register returned empty client_id")
	}
	return id
}

// authorize POSTs the approval form and returns the redirect Location.
func (h *oauthHarness) authorize(t *testing.T, clientID, pairingCode string) *url.URL {
	t.Helper()
	form := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirect},
		"response_type":         {"code"},
		"code_challenge":        {challengeFor(testVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
		"scope":                 {"mcp"},
		"pairing_code":          {pairingCode},
	}
	resp, err := h.client.PostForm(h.url(AuthorizePath), form)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302 (got body? check pairing code)", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("bad redirect Location: %v", err)
	}
	if loc.Query().Get("state") != "xyz" {
		t.Errorf("redirect missing state: %s", loc)
	}
	return loc
}

// exchange runs the token endpoint for an authorization code.
func (h *oauthHarness) exchange(t *testing.T, clientID, code string) map[string]any {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"client_id":     {clientID},
		"code_verifier": {testVerifier},
	}
	resp, err := h.client.PostForm(h.url(TokenPath), form)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func (h *oauthHarness) callMCP(t *testing.T, accessToken string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.url("/mcp"), nil)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("call /mcp: %v", err)
	}
	return resp
}

func TestFullAuthorizationCodeFlow(t *testing.T) {
	h := newHarness(t)
	pairing, _ := h.srv.PairingCode()

	clientID := h.registerClient(t)
	loc := h.authorize(t, clientID, pairing)
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no authorization code in redirect")
	}

	tokens := h.exchange(t, clientID, code)
	access, _ := tokens["access_token"].(string)
	refresh, _ := tokens["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("missing tokens: %v", tokens)
	}
	if tokens["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", tokens["token_type"])
	}

	// The access token unlocks /mcp.
	resp := h.callMCP(t, access)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/mcp with token = %d, want 200", resp.StatusCode)
	}

	// Refresh yields a new access token; the old refresh token is rotated out.
	rForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}}
	rResp := h.postForm(t, TokenPath, rForm)
	defer rResp.Body.Close()
	if rResp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200", rResp.StatusCode)
	}
	var refreshed map[string]any
	_ = json.NewDecoder(rResp.Body).Decode(&refreshed)
	if refreshed["access_token"] == "" {
		t.Error("refresh produced no access token")
	}
	// Reusing the rotated refresh token must fail.
	again := h.postForm(t, TokenPath, rForm)
	defer again.Body.Close()
	if again.StatusCode == http.StatusOK {
		t.Error("rotated refresh token was accepted twice")
	}
}

func TestAuthorizeWrongPairingCodeRerendersForm(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerClient(t)
	form := url.Values{
		"client_id": {clientID}, "redirect_uri": {testRedirect}, "response_type": {"code"},
		"code_challenge": {challengeFor(testVerifier)}, "code_challenge_method": {"S256"},
		"pairing_code": {"mcp-00000-00000-00000-00000-00000"},
	}
	resp := h.postForm(t, AuthorizePath, form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { // form re-rendered, not a redirect
		t.Fatalf("status = %d, want 200 (form re-render)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Incorrect pairing code") {
		t.Error("re-rendered form missing the error message")
	}
}

func TestTokenRejectsBadPKCE(t *testing.T) {
	h := newHarness(t)
	pairing, _ := h.srv.PairingCode()
	clientID := h.registerClient(t)
	code := h.authorize(t, clientID, pairing).Query().Get("code")

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect},
		"client_id": {clientID}, "code_verifier": {"the-WRONG-verifier"},
	}
	resp := h.postForm(t, TokenPath, form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad-PKCE token status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeUnknownClientIsFatal(t *testing.T) {
	h := newHarness(t)
	resp := h.get(t, AuthorizePath+"?client_id=nope&redirect_uri="+url.QueryEscape(testRedirect)+"&response_type=code")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown client status = %d, want 400", resp.StatusCode)
	}
}

// TestAuthorizeMismatchedRedirectIsFatal is the open-redirect guard: a registered
// client presenting a redirect_uri it never registered must hit a fatal error
// page (400) with no Location — the auth code is never redirected anywhere, so it
// can't be exfiltrated to an attacker-controlled URL.
func TestAuthorizeMismatchedRedirectIsFatal(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerClient(t) // registers testRedirect only
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"https://evil.example/cb"},
		"response_type":         {"code"},
		"code_challenge":        {challengeFor(testVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
		"scope":                 {"mcp"},
	}
	resp := h.get(t, AuthorizePath+"?"+q.Encode())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("mismatched redirect status = %d, want 400", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("must not redirect on an unregistered redirect_uri, got Location=%q", loc)
	}
}

func TestConsumedCodeCannotBeReused(t *testing.T) {
	h := newHarness(t)
	pairing, _ := h.srv.PairingCode()
	clientID := h.registerClient(t)
	code := h.authorize(t, clientID, pairing).Query().Get("code")

	_ = h.exchange(t, clientID, code) // first exchange succeeds (asserts 200 within)

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect},
		"client_id": {clientID}, "code_verifier": {testVerifier},
	}
	resp := h.postForm(t, TokenPath, form)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("authorization code was accepted a second time (must be single-use)")
	}
}

func TestValidRedirectURI(t *testing.T) {
	good := []string{
		"https://app.example/cb", "https://app.example/cb?x=1",
		"http://localhost:8080/cb", "http://127.0.0.1/cb", "http://[::1]/cb",
	}
	bad := []string{
		"http://evil.example/cb", // non-loopback http
		"ftp://app.example/cb",   // wrong scheme
		"/relative", "https://", "not a url", "",
	}
	for _, u := range good {
		if !validRedirectURI(u) {
			t.Errorf("validRedirectURI(%q) = false, want true", u)
		}
	}
	for _, u := range bad {
		if validRedirectURI(u) {
			t.Errorf("validRedirectURI(%q) = true, want false", u)
		}
	}
}

func TestAuthorizeParamErrorsRedirect(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerClient(t)
	base := AuthorizePath + "?client_id=" + clientID + "&redirect_uri=" + url.QueryEscape(testRedirect) + "&state=s"
	cases := map[string]string{
		base + "&response_type=token&code_challenge=" + challengeFor(testVerifier) + "&code_challenge_method=S256": "unsupported_response_type",
		base + "&response_type=code": "invalid_request", // missing code_challenge
		base + "&response_type=code&code_challenge=x&code_challenge_method=plain": "invalid_request",
	}
	for u, wantErr := range cases {
		resp := h.get(t, u)
		if resp.StatusCode != http.StatusFound {
			resp.Body.Close()
			t.Errorf("status = %d, want 302 redirect for %s", resp.StatusCode, u)
			continue
		}
		loc, _ := url.Parse(resp.Header.Get("Location"))
		resp.Body.Close()
		if got := loc.Query().Get("error"); got != wantErr {
			t.Errorf("error = %q, want %q for %s", got, wantErr, u)
		}
		if loc.Query().Get("state") != "s" {
			t.Errorf("state not preserved on the error redirect for %s", u)
		}
	}
}

func TestRegisterBodyTooLarge(t *testing.T) {
	h := newHarness(t)
	big := strings.Repeat("a", 70<<10) // > maxRegisterBody (64 KiB)
	body := `{"redirect_uris":["` + testRedirect + `"],"client_name":"` + big + `"}`
	resp, err := h.client.Post(h.url(RegisterPath), "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("oversized register body = %d, want 400", resp.StatusCode)
	}
}

func TestRefreshClientIDMismatch(t *testing.T) {
	h := newHarness(t)
	pairing, _ := h.srv.PairingCode()
	clientID := h.registerClient(t)
	code := h.authorize(t, clientID, pairing).Query().Get("code")
	refresh, _ := h.exchange(t, clientID, code)["refresh_token"].(string)

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"someone-else"}}
	resp := h.postForm(t, TokenPath, form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("refresh with mismatched client_id = %d, want 400", resp.StatusCode)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	if _, err := New(Config{PublicURL: testPublicURL}); err == nil {
		t.Error("New without Store should error")
	}
	if _, err := New(Config{Store: NewMemStore()}); err == nil {
		t.Error("New without PublicURL should error")
	}
}

func TestResourceDefaultsToPublicURL(t *testing.T) {
	h := newHarness(t) // no Resource configured
	if h.srv.resource != testPublicURL {
		t.Errorf("resource = %q, want %q (default to PublicURL)", h.srv.resource, testPublicURL)
	}
	// With a bare-host resource there is no path-suffixed metadata document.
	resp := h.get(t, ProtectedResourceMetadataPath+"/mcp")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("suffixed PRM with default resource = %d, want 404", resp.StatusCode)
	}
}

// TestResourceBindsToMCPEndpoint covers the fix for the Claude connector: the
// protected-resource identifier and token audience are the /mcp endpoint (not the
// bare host), the AS stays the bare host, the RFC 9728 path-suffixed metadata is
// served, and the 401 challenge points at it.
func TestResourceBindsToMCPEndpoint(t *testing.T) {
	const resource = testPublicURL + "/mcp"
	store := NewMemStore()
	srv, err := New(Config{Store: store, PublicURL: testPublicURL, Resource: resource})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	mux.Handle("/mcp", srv.Protect(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	ts := httptest.NewServer(mux)
	defer ts.Close()
	client := ts.Client()

	getJSON := func(path string) map[string]any {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
		}
		var m map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return m
	}

	// PRM advertises the /mcp endpoint as the resource; the AS stays the bare host.
	prm := getJSON(ProtectedResourceMetadataPath)
	if prm["resource"] != resource {
		t.Errorf("PRM resource = %v, want %s", prm["resource"], resource)
	}
	if as, _ := prm["authorization_servers"].([]any); len(as) != 1 || as[0] != testPublicURL {
		t.Errorf("authorization_servers = %v, want [%s]", prm["authorization_servers"], testPublicURL)
	}

	// The RFC 9728 path-suffixed metadata document is served and agrees.
	if sub := getJSON(ProtectedResourceMetadataPath + "/mcp"); sub["resource"] != resource {
		t.Errorf("suffixed PRM resource = %v, want %s", sub["resource"], resource)
	}

	// The 401 challenge points at the path-suffixed metadata, not the bare one.
	resp, err := client.Get(ts.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	wantMeta := ProtectedResourceMetadataPath + "/mcp"
	if wa := resp.Header.Get("WWW-Authenticate"); !strings.Contains(wa, wantMeta) {
		t.Errorf("challenge = %q, want resource_metadata containing %q", wa, wantMeta)
	}

	// Tokens are bound to the resource audience: a server sharing the signing key
	// but bound to the bare-host audience must reject them.
	if srv.issuer.audience != resource {
		t.Errorf("issuer audience = %q, want %q", srv.issuer.audience, resource)
	}
	tok, _, err := srv.issuer.Mint("client-1", "mcp", PrincipalGrant{})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := srv.issuer.Validate(tok); err != nil {
		t.Errorf("resource-bound token rejected by its own issuer: %v", err)
	}
	bareHost, err := New(Config{Store: store, PublicURL: testPublicURL}) // same key, audience = bare host
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := bareHost.issuer.Validate(tok); err == nil {
		t.Error("token bound to the /mcp resource was accepted by a bare-host-audience server")
	}
}

// Protect must attach the validated identity to the request context — the
// hook the MCP layer uses to bind a caller to per-principal credentials.
// Discarding it (the pre-multi-user behavior) breaks identity binding.
func TestProtectAttachesPrincipalToContext(t *testing.T) {
	srv, err := New(Config{Store: NewMemStore(), PublicURL: testPublicURL})
	if err != nil {
		t.Fatal(err)
	}
	var got *Verified
	mux := http.NewServeMux()
	mux.Handle("/mcp", srv.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := PrincipalFrom(r.Context()); ok {
			got = &v
		}
	})))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	tok, _, err := srv.issuer.Mint("client-42", "mcp", PrincipalGrant{})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got == nil {
		t.Fatal("handler saw no principal in the request context")
	}
	if got.ClientID != "client-42" || got.Scope != "mcp" {
		t.Errorf("principal = %+v", got)
	}
}

func TestPrincipalFromEmptyContext(t *testing.T) {
	if _, ok := PrincipalFrom(context.Background()); ok {
		t.Error("expected no principal on a bare context")
	}
}
