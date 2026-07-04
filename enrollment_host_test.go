package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Host-mode enrollment: one AS fronting several mounts, each with its own
// per-resource enrollment whose callback (the host's bridge to `<tool> mcp
// enroll`) returns a namespaced binding. The gate is per-resource — bound for
// lin is still unbound for slack — and enrollment merges into the principal
// record instead of replacing it.

// hostEnrollHarness builds a two-mount host AS: BindingForResource strips the
// mount's namespace, EnrollmentForResource serves a slack-only enrollment
// whose callback records the request and returns a namespaced binding.
func hostEnrollHarness(t *testing.T, got *EnrollRequest) *oauthHarness {
	t.Helper()
	mountOf := map[string]string{maSlack: "slack", maLin: "lin"}
	slackEnrollment := &Enrollment{
		Descriptor: CredentialDescriptor{
			Title: "Connect Slack",
			Modes: []CredentialMode{{
				Key: "token", Label: "API token",
				Fields: []CredentialField{{Key: "token", Label: "API token", Secret: true}},
			}},
		},
		// The host bridge namespaces the tool's returned binding before it
		// lands on the shared principal record.
		Enroll: func(_ context.Context, req EnrollRequest) (EnrollResult, error) {
			*got = req
			return EnrollResult{Binding: map[string]string{"slack:workspace": "acme"}}, nil
		},
	}
	if err := slackEnrollment.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	srv, err := New(Config{
		Store:      NewMemStore(),
		PublicURL:  maHost,
		Resources:  []string{maSlack, maLin},
		Asymmetric: true,
		BindingForResource: func(binding map[string]string, resource string) map[string]string {
			prefix := mountOf[resource] + ":"
			out := map[string]string{}
			for k, v := range binding {
				switch {
				case strings.HasPrefix(k, prefix):
					out[strings.TrimPrefix(k, prefix)] = v
				case !strings.Contains(k, ":"):
					out[k] = v
				}
			}
			if len(out) == 0 {
				return nil
			}
			return out
		},
		EnrollmentForResource: func(resource string) *Enrollment {
			if resource == maSlack {
				return slackEnrollment
			}
			return nil // lin: no enrollment; operator pre-binds
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

// Bound for lin ≠ bound for slack: the same principal is diverted into
// enrollment at the slack mount and approved straight through at lin.
func TestHostEnrollmentGateIsPerResource(t *testing.T) {
	var got EnrollRequest
	h := hostEnrollHarness(t, &got)
	aliceCode, err := h.srv.pairing.AddPrincipal("alice", map[string]string{"lin:workspace": "letsdothis"})
	if err != nil {
		t.Fatal(err)
	}
	clientID := h.registerClient(t)

	// slack: projected binding is empty → the enrollment form renders.
	form := authForm(clientID, aliceCode)
	form.Set("resource", maSlack)
	status, body, _ := h.postAuthorize(t, form)
	if status != http.StatusOK || !strings.Contains(body, `name="enroll" value="1"`) {
		t.Errorf("slack authorize: status=%d, want the enrollment form; body: %.200s", status, body)
	}
	if !strings.Contains(body, "Connect Slack") {
		t.Errorf("slack authorize should render slack's own descriptor; body: %.200s", body)
	}

	// lin: projected binding is non-empty (and lin has no enrollment) → 302.
	form = authForm(clientID, aliceCode)
	form.Set("resource", maLin)
	status, _, loc := h.postAuthorize(t, form)
	if status != http.StatusFound || loc == "" {
		t.Errorf("lin authorize: status=%d loc=%q, want 302 straight through", status, loc)
	}
}

// Already bound FOR THIS RESOURCE → no divert: enrollment is idempotent in
// host mode. The projected binding is non-empty, so the same principal that
// would be diverted when unbound sails straight through to the redirect.
func TestHostEnrollmentSkipsWhenBoundForResource(t *testing.T) {
	var got EnrollRequest
	h := hostEnrollHarness(t, &got)
	aliceCode, err := h.srv.pairing.AddPrincipal("alice",
		map[string]string{"slack:workspace": "acme", "lin:workspace": "letsdothis"})
	if err != nil {
		t.Fatal(err)
	}
	clientID := h.registerClient(t)

	form := authForm(clientID, aliceCode)
	form.Set("resource", maSlack)
	status, body, loc := h.postAuthorize(t, form)
	if status != http.StatusFound || loc == "" {
		t.Errorf("bound-for-slack authorize: status=%d loc=%q, want 302 straight through", status, loc)
	}
	if strings.Contains(body, `name="enroll"`) {
		t.Errorf("bound principal should not see the enrollment form again")
	}
	if got.Principal != "" {
		t.Errorf("enrollment callback must not run for a bound principal, but saw %+v", got)
	}
}

// Completing slack's enrollment merges into the record (lin keys survive) and
// the issued token carries the projected slack binding.
func TestHostEnrollmentMergesAndProjects(t *testing.T) {
	var got EnrollRequest
	h := hostEnrollHarness(t, &got)
	aliceCode, err := h.srv.pairing.AddPrincipal("alice", map[string]string{"lin:workspace": "letsdothis"})
	if err != nil {
		t.Fatal(err)
	}
	clientID := h.registerClient(t)

	form := authForm(clientID, aliceCode)
	form.Set("resource", maSlack)
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set(fieldInputName("token", "token"), "xoxc-sekrit")
	status, _, loc := h.postAuthorize(t, form)
	if status != http.StatusFound || loc == "" {
		t.Fatalf("enroll submit: status=%d loc=%q, want 302", status, loc)
	}
	if got.Principal != "alice" || got.Values["token"] != "xoxc-sekrit" {
		t.Errorf("bridge callback request = %+v", got)
	}

	// Merge, not replace: both tools' keys on the record now.
	principals, _ := h.srv.pairing.Principals()
	if principals["alice"]["lin:workspace"] != "letsdothis" || principals["alice"]["slack:workspace"] != "acme" {
		t.Errorf("persisted binding = %v, want lin AND slack keys", principals["alice"])
	}

	// The issued token is slack-audience and carries the projected binding.
	locURL, _ := url.Parse(loc)
	tokens := h.exchange(t, clientID, locURL.Query().Get("code"))
	verifier, err := NewEd25519Verifier(maHost, maSlack, h.srv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	v, err := verifier.Validate(tokens["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if v.Binding["workspace"] != "acme" || v.Binding["slack:workspace"] != "" || v.Binding["lin:workspace"] != "" {
		t.Errorf("token binding = %v, want projected workspace=acme only", v.Binding)
	}
}

func TestMergePrincipalBinding(t *testing.T) {
	p := NewPairing(NewMemStore())
	if _, err := p.AddPrincipal("alice", map[string]string{"lin:workspace": "x", "shared": "s"}); err != nil {
		t.Fatal(err)
	}
	merged, found, err := p.MergePrincipalBinding("alice", map[string]string{"slack:workspace": "acme", "shared": "s2"})
	if err != nil || !found {
		t.Fatalf("merge: found=%v err=%v", found, err)
	}
	want := map[string]string{"lin:workspace": "x", "shared": "s2", "slack:workspace": "acme"}
	for k, v := range want {
		if merged[k] != v {
			t.Errorf("merged[%s] = %q, want %q", k, merged[k], v)
		}
	}
	if _, found, _ := p.MergePrincipalBinding("nobody", map[string]string{"k": "v"}); found {
		t.Error("merge must never create membership")
	}
}
