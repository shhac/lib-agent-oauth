package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// testEnrollment is a single-mode descriptor: one secret token + an optional
// region, enrolling into the given callback.
func testEnrollment(enroll EnrollFunc) *Enrollment {
	return &Enrollment{
		Descriptor: CredentialDescriptor{
			Title: "Connect Widget",
			Intro: "Stored on the operator's machine.",
			Modes: []CredentialMode{{
				Key: "token", Label: "API token",
				Fields: []CredentialField{
					{Key: "token", Label: "API token", Secret: true},
					{Key: "region", Label: "Region", Optional: true},
				},
			}},
		},
		Enroll: enroll,
	}
}

func newEnrollHarness(t *testing.T, e *Enrollment) *oauthHarness {
	t.Helper()
	srv, err := New(Config{Store: NewMemStore(), PublicURL: testPublicURL, Enrollment: e})
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

// authForm is the base authorize POST body for clientID + pairing code.
func authForm(clientID, pairingCode string) url.Values {
	return url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirect},
		"response_type":         {"code"},
		"code_challenge":        {challengeFor(testVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
		"scope":                 {"mcp"},
		"pairing_code":          {pairingCode},
	}
}

// postAuthorize POSTs the form and returns status + body + Location.
func (h *oauthHarness) postAuthorize(t *testing.T, form url.Values) (int, string, string) {
	t.Helper()
	resp := h.postForm(t, AuthorizePath, form)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header.Get("Location")
}

func TestEnrollmentDescriptorValidation(t *testing.T) {
	enroll := func(context.Context, EnrollRequest) (EnrollResult, error) { return EnrollResult{}, nil }
	bad := []*Enrollment{
		{Descriptor: CredentialDescriptor{Modes: []CredentialMode{{Key: "a", Fields: []CredentialField{{Key: "x"}}}}}}, // nil callback
		{Enroll: enroll},                                            // no modes
		{Enroll: enroll, Descriptor: CredentialDescriptor{Modes: []CredentialMode{{Key: "a"}}}},                        // no fields
		{Enroll: enroll, Descriptor: CredentialDescriptor{Modes: []CredentialMode{{Fields: []CredentialField{{Key: "x"}}}}}}, // empty mode key
		{Enroll: enroll, Descriptor: CredentialDescriptor{Modes: []CredentialMode{{Key: "a", Fields: []CredentialField{{Key: ""}}}}}}, // empty field key
		{Enroll: enroll, Descriptor: CredentialDescriptor{Modes: []CredentialMode{
			{Key: "a", Fields: []CredentialField{{Key: "x"}}}, {Key: "a", Fields: []CredentialField{{Key: "x"}}}}}}, // dup mode
		{Enroll: enroll, Descriptor: CredentialDescriptor{Modes: []CredentialMode{
			{Key: "a", Fields: []CredentialField{{Key: "x"}, {Key: "x"}}}}}}, // dup field
	}
	for i, e := range bad {
		if _, err := New(Config{Store: NewMemStore(), PublicURL: testPublicURL, Enrollment: e}); err == nil {
			t.Errorf("case %d: invalid enrollment accepted", i)
		}
	}
	if _, err := New(Config{Store: NewMemStore(), PublicURL: testPublicURL, Enrollment: testEnrollment(enroll)}); err != nil {
		t.Errorf("valid enrollment rejected: %v", err)
	}
}

// A field's Snippet renders as a distinct, escaped code block with a copy
// button; a field without one gets no block.
func TestEnrollFieldSnippetRenders(t *testing.T) {
	e := &Enrollment{
		Descriptor: CredentialDescriptor{
			Modes: []CredentialMode{{
				Key: "m",
				Fields: []CredentialField{
					{Key: "token", Label: "Token", Secret: true, Help: "run this:", Snippet: "console.log(1 > 0)"},
					{Key: "plain", Label: "Plain"},
				},
			}},
		},
		Enroll: func(context.Context, EnrollRequest) (EnrollResult, error) {
			return EnrollResult{Binding: map[string]string{"k": "v"}}, nil
		},
	}
	h := newEnrollHarness(t, e)
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	status, body, _ := h.postAuthorize(t, authForm(clientID, code))
	if status != http.StatusOK {
		t.Fatalf("status=%d, want the enrollment form", status)
	}
	// The snippet is HTML-escaped (the ">" becomes &gt;) inside a code block.
	if !strings.Contains(body, `<div class="snippet"><pre>console.log(1 &gt; 0)`) {
		t.Errorf("snippet code block missing or unescaped:\n%s", body)
	}
	if !strings.Contains(body, "navigator.clipboard.writeText") {
		t.Error("copy button missing")
	}
	// Exactly one field carries a snippet; the plain field must not.
	if n := strings.Count(body, `class="snippet"`); n != 1 {
		t.Errorf("expected exactly one snippet block, got %d", n)
	}
}

// An unbound named principal is diverted to the enrollment form instead of
// being redirected — and no authorization code is issued.
func TestEnrollFormRendersForUnboundPrincipal(t *testing.T) {
	h := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		t.Error("callback must not run before the enrollment POST")
		return EnrollResult{}, nil
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	status, body, loc := h.postAuthorize(t, authForm(clientID, code))
	if status != http.StatusOK || loc != "" {
		t.Fatalf("status=%d loc=%q, want 200 enrollment page with no redirect", status, loc)
	}
	for _, want := range []string{"Connect Widget", "API token", "alice", `name="enroll" value="1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("enrollment page missing %q", want)
		}
	}
}

// The anonymous operator (shared code) never sees enrollment.
func TestAnonymousOperatorSkipsEnrollment(t *testing.T) {
	h := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		t.Error("callback must not run for the anonymous operator")
		return EnrollResult{}, nil
	}))
	shared, _ := h.srv.PairingCode()
	clientID := h.registerClient(t)
	status, _, loc := h.postAuthorize(t, authForm(clientID, shared))
	if status != http.StatusFound || !strings.Contains(loc, "code=") {
		t.Errorf("status=%d loc=%q, want 302 with a code", status, loc)
	}
}

// A bound principal is redirected as before — unless they asked to update.
func TestBoundPrincipalSkipsEnrollmentUnlessUpdating(t *testing.T) {
	h := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		return EnrollResult{Binding: map[string]string{"workspace": "alice"}}, nil
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", map[string]string{"workspace": "alice"})
	clientID := h.registerClient(t)

	status, _, loc := h.postAuthorize(t, authForm(clientID, code))
	if status != http.StatusFound || loc == "" {
		t.Fatalf("bound principal: status=%d, want 302", status)
	}

	form := authForm(clientID, code)
	form.Set("update_credentials", "1")
	status, body, _ := h.postAuthorize(t, form)
	if status != http.StatusOK || !strings.Contains(body, "Connect Widget") {
		t.Errorf("update_credentials: status=%d, want the enrollment form", status)
	}
}

// The full happy path: form → callback → binding persisted → code → tokens
// carrying the fresh binding.
func TestEnrollSubmitHappyPath(t *testing.T) {
	var got EnrollRequest
	h := newEnrollHarness(t, testEnrollment(func(_ context.Context, req EnrollRequest) (EnrollResult, error) {
		got = req
		return EnrollResult{Binding: map[string]string{"workspace": "alice"}}, nil
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	form := authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set(fieldInputName("token", "token"), "sk-sekrit")
	form.Set(fieldInputName("token", "region"), "eu")
	status, _, loc := h.postAuthorize(t, form)
	if status != http.StatusFound || loc == "" {
		t.Fatalf("enroll submit: status=%d loc=%q, want 302", status, loc)
	}

	if got.Principal != "alice" || got.Mode != "token" ||
		got.Values["token"] != "sk-sekrit" || got.Values["region"] != "eu" {
		t.Errorf("callback request = %+v", got)
	}

	// Binding persisted on the pairing record.
	principals, _ := h.srv.pairing.Principals()
	if principals["alice"]["workspace"] != "alice" {
		t.Errorf("persisted binding = %v", principals["alice"])
	}

	// The issued tokens carry the fresh binding.
	locURL, _ := url.Parse(loc)
	tokens := h.exchange(t, clientID, locURL.Query().Get("code"))
	v, err := h.srv.issuer.Validate(tokens["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "alice" || v.Binding["workspace"] != "alice" {
		t.Errorf("token principal = %+v", v.PrincipalGrant)
	}
}

// A callback error re-renders the form: message shown, non-secret values
// preserved, the secret never echoed.
func TestEnrollSubmitCallbackErrorRerenders(t *testing.T) {
	h := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		return EnrollResult{}, errors.New("service rejected these credentials")
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	form := authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set(fieldInputName("token", "token"), "sk-sekrit")
	form.Set(fieldInputName("token", "region"), "eu")
	status, body, _ := h.postAuthorize(t, form)
	if status != http.StatusOK {
		t.Fatalf("status=%d, want 200 re-render", status)
	}
	if !strings.Contains(body, "service rejected these credentials") {
		t.Error("re-render missing the callback error")
	}
	if strings.Contains(body, "sk-sekrit") {
		t.Error("secret value echoed back into the page")
	}
	if !strings.Contains(body, `value="eu"`) {
		t.Error("non-secret value not preserved")
	}
	// And nothing was bound.
	principals, _ := h.srv.pairing.Principals()
	if len(principals["alice"]) != 0 {
		t.Errorf("binding written despite callback error: %v", principals["alice"])
	}
}

func TestEnrollMissingRequiredField(t *testing.T) {
	called := false
	h := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		called = true
		return EnrollResult{}, nil
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	form := authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token") // required "token" field left empty
	status, body, _ := h.postAuthorize(t, form)
	if status != http.StatusOK || !strings.Contains(body, "Required") {
		t.Errorf("status=%d, want 200 with a Required error", status)
	}
	if called {
		t.Error("callback ran despite a missing required field")
	}
}

// The Choice arm: first round returns options, the chooser renders them, the
// follow-up POST reaches the callback with Choice + State, and the returned
// binding finishes the flow.
func TestEnrollChoiceRoundTrip(t *testing.T) {
	var followUp EnrollRequest
	h := newEnrollHarness(t, testEnrollment(func(_ context.Context, req EnrollRequest) (EnrollResult, error) {
		if req.Choice == "" {
			return EnrollResult{Choice: &EnrollChoice{
				Prompt: "Which team?",
				Options: []ChoiceOption{
					{Value: "personal", Label: "Personal account"},
					{Value: "acme", Label: "Acme Corp"},
				},
				State: "opaque-callback-state",
			}}, nil
		}
		followUp = req
		return EnrollResult{Binding: map[string]string{"team": req.Choice}}, nil
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	// Round 1: fields → chooser page.
	form := authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set(fieldInputName("token", "token"), "sk-x")
	status, body, _ := h.postAuthorize(t, form)
	if status != http.StatusOK {
		t.Fatalf("choice round 1: status=%d, want 200 chooser", status)
	}
	for _, want := range []string{"Which team?", "Acme Corp", "opaque-callback-state", `name="enroll_choice_round" value="1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("chooser missing %q", want)
		}
	}

	// Round 2: selection → binding → redirect.
	form = authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set("enroll_choice_round", "1")
	form.Set("enroll_choice", "acme")
	form.Set("enroll_state", "opaque-callback-state")
	status, _, loc := h.postAuthorize(t, form)
	if status != http.StatusFound || loc == "" {
		t.Fatalf("choice round 2: status=%d, want 302", status)
	}
	if followUp.Principal != "alice" || followUp.Choice != "acme" || followUp.State != "opaque-callback-state" {
		t.Errorf("follow-up request = %+v", followUp)
	}
	if len(followUp.Values) != 0 {
		t.Errorf("follow-up must not carry field values, got %v", followUp.Values)
	}
	principals, _ := h.srv.pairing.Principals()
	if principals["alice"]["team"] != "acme" {
		t.Errorf("persisted binding = %v", principals["alice"])
	}
}

// A set-valued binding diverts to the chooser; the chosen singleton rides in
// the token; a forged unoffered choice is refused against the stored set.
func TestBindingSetChooser(t *testing.T) {
	h := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		t.Error("enrollment callback must not run for a bound principal")
		return EnrollResult{}, nil
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", map[string]string{"workspace": "acme,personal"})
	clientID := h.registerClient(t)

	// No choice yet → chooser page listing exactly the granted set.
	status, body, _ := h.postAuthorize(t, authForm(clientID, code))
	if status != http.StatusOK {
		t.Fatalf("status=%d, want 200 chooser", status)
	}
	for _, want := range []string{"acme", "personal", `name="choose" value="1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("chooser missing %q", want)
		}
	}

	// Forged choice outside the set → re-render, no code issued.
	form := authForm(clientID, code)
	form.Set("choose", "1")
	form.Set("choice_workspace", "operator-personal")
	status, _, loc := h.postAuthorize(t, form)
	if status != http.StatusOK || loc != "" {
		t.Fatalf("forged choice: status=%d loc=%q, want re-rendered chooser", status, loc)
	}

	// Valid choice → 302; the token carries the chosen singleton, and the
	// stored record keeps the full set.
	form.Set("choice_workspace", "acme")
	status, _, loc = h.postAuthorize(t, form)
	if status != http.StatusFound {
		t.Fatalf("valid choice: status=%d, want 302", status)
	}
	locURL, _ := url.Parse(loc)
	tokens := h.exchange(t, clientID, locURL.Query().Get("code"))
	v, err := h.srv.issuer.Validate(tokens["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if v.Binding["workspace"] != "acme" {
		t.Errorf("token binding = %v, want the chosen singleton", v.Binding)
	}
	principals, _ := h.srv.pairing.Principals()
	if principals["alice"]["workspace"] != "acme,personal" {
		t.Errorf("stored binding = %v, want the full set kept", principals["alice"])
	}
}

// Set parsing + choice resolution unit coverage.
func TestBindingSetHelpers(t *testing.T) {
	if _, ok := bindingSet("acme"); ok {
		t.Error("singleton treated as a set")
	}
	if members, ok := bindingSet(" acme , personal "); !ok || len(members) != 2 || members[0] != "acme" {
		t.Errorf("bindingSet = %v ok=%v", members, ok)
	}
	if _, ok := bindingSet("acme,"); ok {
		t.Error("trailing separator with one member treated as a set")
	}

	binding := map[string]string{"workspace": "a,b", "region": "eu"}
	resolved, ok := resolveBindingChoices(binding, func(string) string { return "b" })
	if !ok || resolved["workspace"] != "b" || resolved["region"] != "eu" {
		t.Errorf("resolved = %v ok=%v", resolved, ok)
	}
	if _, ok := resolveBindingChoices(binding, func(string) string { return "zzz" }); ok {
		t.Error("unoffered choice resolved")
	}
}

// The enrollment POST is still gated by the pairing code: a bad code with
// enroll=1 re-renders the code form and never reaches the callback.
func TestEnrollPostStillRequiresPairingCode(t *testing.T) {
	called := false
	h := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		called = true
		return EnrollResult{}, nil
	}))
	_, _ = h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	form := authForm(clientID, "mcp-00000-00000-00000-00000-00000")
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set(fieldInputName("token", "token"), "x")
	status, body, _ := h.postAuthorize(t, form)
	if status != http.StatusOK || !strings.Contains(body, "Incorrect pairing code") {
		t.Errorf("status=%d, want the code form re-rendered", status)
	}
	if called {
		t.Error("callback ran with an invalid pairing code")
	}
}

// A callback that returns neither binding nor choice is a contract violation.
func TestEnrollEmptyResultIsError(t *testing.T) {
	h := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		return EnrollResult{}, nil
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	form := authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set(fieldInputName("token", "token"), "x")
	status, _, _ := h.postAuthorize(t, form)
	if status != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 for an empty enrollment result", status)
	}
}

// Two modes sharing a field key must not shadow each other's inputs.
func TestEnrollTwoModesFieldNamespacing(t *testing.T) {
	var got EnrollRequest
	e := &Enrollment{
		Descriptor: CredentialDescriptor{Modes: []CredentialMode{
			{Key: "a", Label: "A", Fields: []CredentialField{{Key: "password", Label: "A password", Secret: true}}},
			{Key: "b", Label: "B", Fields: []CredentialField{{Key: "password", Label: "B password", Secret: true}}},
		}},
		Enroll: func(_ context.Context, req EnrollRequest) (EnrollResult, error) {
			got = req
			return EnrollResult{Binding: map[string]string{"k": "v"}}, nil
		},
	}
	h := newEnrollHarness(t, e)
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	form := authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "b")
	form.Set(fieldInputName("a", "password"), "wrong-mode-value")
	form.Set(fieldInputName("b", "password"), "right-mode-value")
	if status, _, _ := h.postAuthorize(t, form); status != http.StatusFound {
		t.Fatalf("status=%d, want 302", status)
	}
	if got.Mode != "b" || got.Values["password"] != "right-mode-value" {
		t.Errorf("callback saw %+v — mode B's field was shadowed", got)
	}
}

func TestSetPrincipalBinding(t *testing.T) {
	p := NewPairing(NewMemStore())
	if ok, err := p.SetPrincipalBinding("ghost", map[string]string{"k": "v"}); err != nil || ok {
		t.Errorf("binding an unknown principal: ok=%v err=%v — must never create membership", ok, err)
	}
	code, _ := p.AddPrincipal("alice", nil)
	if ok, err := p.SetPrincipalBinding("alice", map[string]string{"workspace": "alice"}); err != nil || !ok {
		t.Fatalf("SetPrincipalBinding: ok=%v err=%v", ok, err)
	}
	grant, ok, _ := p.VerifyPrincipal(code)
	if !ok || grant.Binding["workspace"] != "alice" {
		t.Errorf("grant after binding = %+v (code must be preserved)", grant)
	}
}

// The code-entry form offers the update checkbox only when enrollment exists.
func TestCodeFormOffersUpdateOnlyWithEnrollment(t *testing.T) {
	withEnroll := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		return EnrollResult{Binding: map[string]string{"k": "v"}}, nil
	}))
	without := newHarness(t)

	page := func(h *oauthHarness) string {
		clientID := h.registerClient(t)
		q := url.Values{
			"client_id": {clientID}, "redirect_uri": {testRedirect}, "response_type": {"code"},
			"code_challenge": {challengeFor(testVerifier)}, "code_challenge_method": {"S256"},
		}
		resp := h.get(t, AuthorizePath+"?"+q.Encode())
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if !strings.Contains(page(withEnroll), "update_credentials") {
		t.Error("enrollment-configured code form missing the update checkbox")
	}
	if strings.Contains(page(without), "update_credentials") {
		t.Error("plain code form must not offer the update checkbox")
	}
}

// A callback that succeeds but whose principal was revoked mid-enrollment
// (SetPrincipalBinding then finds nothing) fails closed: an error page, and no
// authorization code is ever issued — the binding can't be persisted, so the
// flow must not complete under a phantom identity.
func TestEnrollBindingForRemovedPrincipalFailsClosed(t *testing.T) {
	var h *oauthHarness
	h = newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		// The principal vanishes between passing the code check and the binding
		// write — e.g. the operator revoked them concurrently.
		_, _ = h.srv.pairing.RemovePrincipal("alice")
		return EnrollResult{Binding: map[string]string{"workspace": "alice"}}, nil
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	form := authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set(fieldInputName("token", "token"), "sk-x")
	status, _, loc := h.postAuthorize(t, form)
	if status != http.StatusBadRequest || loc != "" {
		t.Fatalf("status=%d loc=%q, want 400 error page with no code issued", status, loc)
	}
}

// A Choice with no options is a callback contract violation → error page.
func TestEnrollChoiceEmptyOptionsIsError(t *testing.T) {
	h := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		return EnrollResult{Choice: &EnrollChoice{Prompt: "Pick one"}}, nil
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	form := authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set(fieldInputName("token", "token"), "sk-x")
	if status, _, _ := h.postAuthorize(t, form); status != http.StatusBadRequest {
		t.Errorf("status=%d, want 400 for a choice with empty options", status)
	}
}

// A choice-round POST with nothing selected re-renders and never calls back.
func TestEnrollChoiceRoundEmptySelectionRerenders(t *testing.T) {
	called := false
	h := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		called = true
		return EnrollResult{}, nil
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	form := authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set("enroll_choice_round", "1")
	form.Set("enroll_choice", "") // nothing picked
	status, body, _ := h.postAuthorize(t, form)
	if status != http.StatusOK || !strings.Contains(body, "No option was selected") {
		t.Errorf("status=%d, want 200 re-render prompting to start again", status)
	}
	if called {
		t.Error("callback ran despite an empty choice selection")
	}
}

// A submission naming a mode that doesn't exist re-renders and never calls back —
// a forged enroll_mode can't smuggle input past the descriptor.
func TestEnrollForgedModeRerenders(t *testing.T) {
	called := false
	h := newEnrollHarness(t, testEnrollment(func(context.Context, EnrollRequest) (EnrollResult, error) {
		called = true
		return EnrollResult{}, nil
	}))
	code, _ := h.srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	form := authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "nonexistent")
	form.Set(fieldInputName("token", "token"), "sk-x")
	status, body, _ := h.postAuthorize(t, form)
	if status != http.StatusOK || !strings.Contains(body, "Pick how you want to authenticate") {
		t.Errorf("status=%d, want 200 re-render asking to pick a mode", status)
	}
	if called {
		t.Error("callback ran for a nonexistent mode")
	}
}
