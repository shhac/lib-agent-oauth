package oauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Session tests: login once (pairing code) → cookie → the next tool skips the
// code and prompts only for its own delta. Cookies are threaded explicitly
// (no jar): the __Host- cookie is Secure, which a jar would refuse to replay
// over the httptest http:// transport.

// sessionHarness is a two-mount host AS with sessions enabled: slack carries
// an enrollment (callback returns a namespaced binding), lin does not.
func sessionHarness(t *testing.T) *oauthHarness {
	t.Helper()
	mountOf := map[string]string{maSlack: "slack", maLin: "lin"}
	slackEnrollment := &Enrollment{
		Descriptor: CredentialDescriptor{
			Title: "Connect Slack",
			Modes: []CredentialMode{{
				Key: "token", Fields: []CredentialField{{Key: "token", Label: "API token", Secret: true}},
			}},
		},
		Enroll: func(_ context.Context, req EnrollRequest) (EnrollResult, error) {
			return EnrollResult{Binding: map[string]string{"slack:workspace": "acme"}}, nil
		},
	}
	srv, err := New(Config{
		Store:      NewMemStore(),
		PublicURL:  maHost,
		Resources:  []string{maSlack, maLin},
		Asymmetric: true,
		SessionTTL: time.Hour,
		BindingForResource: func(binding map[string]string, resource string) map[string]string {
			return stripPrefixBinding(binding, mountOf[resource])
		},
		EnrollmentForResource: func(resource string) *Enrollment {
			if resource == maSlack {
				return slackEnrollment
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &oauthHarness{srv: srv, http: ts, client: client}
}

// postAuthorizeCookie POSTs the authorize form with a session cookie attached.
func (h *oauthHarness) postAuthorizeCookie(t *testing.T, form url.Values, cookie string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.url(AuthorizePath), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		req.Header.Set("Cookie", sessionCookie+"="+cookie)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// sessionCookieFrom pulls the session token out of a response's Set-Cookie.
func sessionCookieFrom(t *testing.T, resp *http.Response) string {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			if !c.HttpOnly || !c.Secure || c.Path != "/" {
				t.Errorf("session cookie attributes: HttpOnly=%v Secure=%v Path=%q", c.HttpOnly, c.Secure, c.Path)
			}
			return c.Value
		}
	}
	return ""
}

// Sessions are strictly opt-in: without SessionTTL a completed flow sets no
// cookie.
func TestNoSessionCookieByDefault(t *testing.T) {
	h, aliceCode := maBindingHarness(t) // SessionTTL unset
	clientID := h.registerClient(t)
	form := authForm(clientID, aliceCode)
	form.Set("resource", maSlack)
	resp := h.postForm(t, AuthorizePath, form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d, want 302", resp.StatusCode)
	}
	if got := sessionCookieFrom(t, resp); got != "" {
		t.Errorf("cookie set with sessions disabled")
	}
}

// The headline: one code entry at lin, then the SLACK connector needs no code
// — the session identifies alice and slack prompts only for its own
// enrollment, whose POST rounds also ride the session.
func TestSessionLoginOnceGrowScope(t *testing.T) {
	h := sessionHarness(t)
	aliceCode, err := h.srv.pairing.AddPrincipal("alice", map[string]string{"lin:workspace": "letsdothis"})
	if err != nil {
		t.Fatal(err)
	}
	clientID := h.registerClient(t)

	// Login once: code entry at the lin mount (bound → straight through).
	form := authForm(clientID, aliceCode)
	form.Set("resource", maLin)
	resp := h.postForm(t, AuthorizePath, form)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("lin authorize = %d, want 302", resp.StatusCode)
	}
	session := sessionCookieFrom(t, resp)
	if session == "" {
		t.Fatal("no session cookie after a code-entered flow")
	}

	// Second tool, GET: recognized by session, code input optional.
	getReq, _ := http.NewRequest(http.MethodGet, h.url(AuthorizePath)+"?"+authForm(clientID, "").Encode()+"&resource="+url.QueryEscape(maSlack), nil)
	getReq.Header.Set("Cookie", sessionCookie+"="+session)
	getResp, err := h.client.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, getResp)
	if getResp.StatusCode != http.StatusOK || !strings.Contains(page, "recognized as <b>alice</b>") {
		t.Errorf("session GET: status=%d, want recognized-as-alice form; body: %.200s", getResp.StatusCode, page)
	}

	// Second tool, POST without a code: unbound for slack → slack's own
	// enrollment form (the delta), not a code demand.
	form = authForm(clientID, "")
	form.Set("resource", maSlack)
	resp = h.postAuthorizeCookie(t, form, session)
	page = readAll(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Connect Slack") {
		t.Fatalf("slack authorize via session = %d, want slack's enrollment form; body: %.200s", resp.StatusCode, page)
	}

	// The enrollment round also rides the session (no code hidden field).
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set(fieldInputName("token", "token"), "xoxc-sekrit")
	resp = h.postAuthorizeCookie(t, form, session)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("enroll via session = %d, want 302", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))

	// The slack token carries the projected fresh binding.
	tokens := h.exchange(t, clientID, loc.Query().Get("code"))
	verifier, err := NewEd25519Verifier(maHost, maSlack, h.srv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	v, err := verifier.Validate(tokens["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "alice" || v.Binding["workspace"] != "acme" {
		t.Errorf("token after session-grown enrollment = %+v", v.PrincipalGrant)
	}

	// A session-resumed flow does not mint a second session cookie.
	if sessionCookieFrom(t, resp) != "" {
		t.Errorf("session-resumed flow re-issued a session cookie")
	}
}

// Removing the principal kills their session — both by purge and by the
// per-use re-resolution.
func TestSessionDiesWithPrincipal(t *testing.T) {
	h := sessionHarness(t)
	code, err := h.srv.pairing.AddPrincipal("mallory", map[string]string{"lin:workspace": "x"})
	if err != nil {
		t.Fatal(err)
	}
	clientID := h.registerClient(t)
	form := authForm(clientID, code)
	form.Set("resource", maLin)
	resp := h.postForm(t, AuthorizePath, form)
	resp.Body.Close()
	session := sessionCookieFrom(t, resp)
	if session == "" {
		t.Fatal("no session")
	}

	if _, err := h.srv.pairing.RemovePrincipal("mallory"); err != nil {
		t.Fatal(err)
	}

	form = authForm(clientID, "")
	form.Set("resource", maLin)
	resp = h.postAuthorizeCookie(t, form, session)
	page := readAll(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Incorrect pairing code") {
		t.Errorf("removed principal's session: status=%d, want the code form back; body: %.200s", resp.StatusCode, page)
	}
}

// An expired session is dead, and an entered code always wins over a session.
func TestSessionExpiryAndCodePrecedence(t *testing.T) {
	h := sessionHarness(t)
	aliceCode, _ := h.srv.pairing.AddPrincipal("alice", map[string]string{"lin:workspace": "a"})
	bobCode, _ := h.srv.pairing.AddPrincipal("bob", map[string]string{"lin:workspace": "b"})
	clientID := h.registerClient(t)

	form := authForm(clientID, aliceCode)
	form.Set("resource", maLin)
	resp := h.postForm(t, AuthorizePath, form)
	resp.Body.Close()
	session := sessionCookieFrom(t, resp)

	// bob's CODE + alice's cookie → bob's token (the entered code wins).
	form = authForm(clientID, bobCode)
	form.Set("resource", maLin)
	resp = h.postAuthorizeCookie(t, form, session)
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	tokens := h.exchange(t, clientID, loc.Query().Get("code"))
	verifier, _ := NewEd25519Verifier(maHost, maLin, h.srv.PublicKey())
	if v, err := verifier.Validate(tokens["access_token"].(string)); err != nil || v.Name != "bob" {
		t.Errorf("code should win over session: v=%+v err=%v", v, err)
	}

	// Expire alice's session and it stops identifying her.
	h.srv.sessions.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	form = authForm(clientID, "")
	form.Set("resource", maLin)
	resp = h.postAuthorizeCookie(t, form, session)
	page := readAll(t, resp)
	if !strings.Contains(page, "Incorrect pairing code") {
		t.Errorf("expired session should fall back to the code form; body: %.200s", page)
	}
}

// The anonymous operator (shared pairing code) gets a session too: the record
// is marked Anonymous — Name == "" is not enough to tell "anonymous" from
// "absent" — the next tool greets "operator", and its token carries the zero
// grant.
func TestSessionAnonymousOperator(t *testing.T) {
	h := sessionHarness(t)
	shared, err := h.srv.PairingCode()
	if err != nil {
		t.Fatal(err)
	}
	clientID := h.registerClient(t)

	// Login once with the SHARED operator code at the lin mount.
	form := authForm(clientID, shared)
	form.Set("resource", maLin)
	resp := h.postForm(t, AuthorizePath, form)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("operator authorize = %d, want 302", resp.StatusCode)
	}
	session := sessionCookieFrom(t, resp)
	if session == "" {
		t.Fatal("no session cookie after the operator's code-entered flow")
	}

	// The next tool recognizes the anonymous operator by session — greeted as
	// "operator", no code demanded.
	getReq, _ := http.NewRequest(http.MethodGet, h.url(AuthorizePath)+"?"+authForm(clientID, "").Encode()+"&resource="+url.QueryEscape(maLin), nil)
	getReq.Header.Set("Cookie", sessionCookie+"="+session)
	getResp, err := h.client.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, getResp)
	if getResp.StatusCode != http.StatusOK || !strings.Contains(page, "recognized as <b>operator</b>") {
		t.Errorf("operator session GET: status=%d, want recognized-as-operator; body: %.200s", getResp.StatusCode, page)
	}

	// A code-less POST rides the session and issues the anonymous grant's token.
	form = authForm(clientID, "")
	form.Set("resource", maLin)
	resp = h.postAuthorizeCookie(t, form, session)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("operator session POST = %d, want 302", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	tokens := h.exchange(t, clientID, loc.Query().Get("code"))
	verifier, _ := NewEd25519Verifier(maHost, maLin, h.srv.PublicKey())
	v, err := verifier.Validate(tokens["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "" {
		t.Errorf("anonymous-operator session token = %+v, want the zero-name grant", v.PrincipalGrant)
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
