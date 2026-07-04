package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Events are the host's operator-facing activity stream: one full grow-scope
// walk (register → pair by code at lin → session → pair by session at slack →
// enroll → authorize) must produce exactly the lifecycle moments, in order,
// with no secrets.
func TestEventsAcrossGrowScopeWalk(t *testing.T) {
	var events []Event
	mountOf := map[string]string{maSlack: "slack", maLin: "lin"}
	slackEnrollment := &Enrollment{
		Descriptor: CredentialDescriptor{Modes: []CredentialMode{{
			Key: "token", Fields: []CredentialField{{Key: "token", Label: "API token", Secret: true}},
		}}},
		Enroll: func(context.Context, EnrollRequest) (EnrollResult, error) {
			return EnrollResult{Binding: map[string]string{"slack:workspace": "acme"}}, nil
		},
	}
	srv, err := New(Config{
		Store:      NewMemStore(),
		PublicURL:  maHost,
		Resources:  []string{maSlack, maLin},
		Asymmetric: true,
		SessionTTL: time.Hour,
		OnEvent:    func(e Event) { events = append(events, e) },
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
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	h := &oauthHarness{srv: srv, http: ts, client: &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}

	aliceCode, err := srv.pairing.AddPrincipal("alice", map[string]string{"lin:workspace": "letsdothis"})
	if err != nil {
		t.Fatal(err)
	}
	clientID := h.registerClient(t)

	// Code entry at lin (bound → straight through).
	form := authForm(clientID, aliceCode)
	form.Set("resource", maLin)
	resp := h.postForm(t, AuthorizePath, form)
	resp.Body.Close()
	session := sessionCookieFrom(t, resp)

	// Session at slack → enrollment → complete.
	form = authForm(clientID, "")
	form.Set("resource", maSlack)
	h.postAuthorizeCookie(t, form, session).Body.Close()
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set(fieldInputName("token", "token"), "xoxc-sekrit")
	h.postAuthorizeCookie(t, form, session).Body.Close()

	want := []Event{
		{Type: EventClientRegistered, Client: "Test Client"},
		{Type: EventPaired, Principal: "alice", Client: "Test Client", Resource: maLin, Via: "code"},
		{Type: EventSessionStarted, Principal: "alice"},
		{Type: EventAuthorized, Principal: "alice", Client: "Test Client", Resource: maLin, Via: "code"},
		{Type: EventPaired, Principal: "alice", Client: "Test Client", Resource: maSlack, Via: "session"},
		{Type: EventEnrolled, Principal: "alice", Client: "Test Client", Resource: maSlack},
		{Type: EventAuthorized, Principal: "alice", Client: "Test Client", Resource: maSlack, Via: "session"},
	}
	if len(events) != len(want) {
		t.Fatalf("got %d events, want %d:\n%+v", len(events), len(want), events)
	}
	for i, w := range want {
		if events[i] != w {
			t.Errorf("event[%d] = %+v, want %+v", i, events[i], w)
		}
	}
	// No secrets anywhere in the stream.
	for _, e := range events {
		for _, v := range []string{e.Type, e.Principal, e.Client, e.Resource, e.Via} {
			if strings.Contains(v, "xoxc") || strings.Contains(v, aliceCode) {
				t.Errorf("event leaked a secret: %+v", e)
			}
		}
	}
}

// stripPrefixBinding is the namespace-strip projection the three host-mode
// test harnesses share.
func stripPrefixBinding(binding map[string]string, mount string) map[string]string {
	prefix := mount + ":"
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
}
