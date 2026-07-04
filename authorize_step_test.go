package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// classifyStep is the single interpretation of the flow's hidden markers —
// pinned exhaustively, including forged combinations, which must classify
// exactly as the pre-classifier dispatch order did.
func TestClassifyStep(t *testing.T) {
	cases := []struct {
		name string
		form url.Values
		want authorizeStep
	}{
		{"no markers", url.Values{}, stepInitialApproval},
		{"unrelated fields only", url.Values{"pairing_code": {"x"}, "state": {"s"}}, stepInitialApproval},
		{"enroll fields", url.Values{"enroll": {"1"}}, stepEnrollFields},
		{"enroll choice", url.Values{"enroll": {"1"}, "enroll_choice_round": {"1"}}, stepEnrollChoice},
		{"binding choice", url.Values{"choose": {"1"}}, stepBindingChoice},
		// Forged / nonsense combinations — precedence mirrors the old dispatch:
		{"enroll wins over choose", url.Values{"enroll": {"1"}, "choose": {"1"}}, stepEnrollFields},
		{"enroll choice wins over choose", url.Values{"enroll": {"1"}, "enroll_choice_round": {"1"}, "choose": {"1"}}, stepEnrollChoice},
		{"orphan choice round is initial", url.Values{"enroll_choice_round": {"1"}}, stepInitialApproval},
		{"marker needs value 1", url.Values{"enroll": {"yes"}, "choose": {"true"}}, stepInitialApproval},
		{"update_credentials is not a step", url.Values{"update_credentials": {"1"}}, stepInitialApproval},
	}
	for _, c := range cases {
		if got := classifyStep(c.form); got != c.want {
			t.Errorf("%s: classifyStep(%v) = %d, want %d", c.name, c.form, got, c.want)
		}
	}
}

// Forged markers over the real HTTP flow: enroll+choose together is ONE
// enrollment round (no paired event, no chooser), and an orphan
// enroll_choice_round is a plain initial approval (paired fires once, no
// choice dispatch).
func TestForgedMarkersOverHTTP(t *testing.T) {
	var events []Event
	var reqs []EnrollRequest
	srv, err := New(Config{
		Store:     NewMemStore(),
		PublicURL: testPublicURL,
		OnEvent:   func(e Event) { events = append(events, e) },
		Enrollment: testEnrollment(func(_ context.Context, req EnrollRequest) (EnrollResult, error) {
			reqs = append(reqs, req)
			return EnrollResult{Binding: map[string]string{"workspace": "w"}}, nil
		}),
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
	code, _ := srv.pairing.AddPrincipal("alice", nil)
	clientID := h.registerClient(t)

	// Forged: enrollment submission ALSO carrying choose=1. One enrollment
	// round: callback runs once with the values, no paired event, 302.
	form := authForm(clientID, code)
	form.Set("enroll", "1")
	form.Set("choose", "1")
	form.Set("enroll_mode", "token")
	form.Set(fieldInputName("token", "token"), "sk-x")
	status, _, loc := h.postAuthorize(t, form)
	if status != http.StatusFound || loc == "" {
		t.Fatalf("forged enroll+choose = %d, want 302", status)
	}
	if len(reqs) != 1 || reqs[0].Values["token"] != "sk-x" || reqs[0].Choice != "" {
		t.Errorf("callback calls = %+v, want one fields round", reqs)
	}
	for _, e := range events {
		if e.Type == EventPaired {
			t.Errorf("paired event fired on an enrollment round: %+v", events)
		}
	}

	// Orphan enroll_choice_round without enroll: a plain initial approval for
	// the now-bound principal — paired fires exactly once, callback untouched.
	events, reqs = nil, nil
	form = authForm(clientID, code)
	form.Set("enroll_choice_round", "1")
	status, _, loc = h.postAuthorize(t, form)
	if status != http.StatusFound || loc == "" {
		t.Fatalf("orphan choice round = %d, want 302 straight approval", status)
	}
	paired := 0
	for _, e := range events {
		if e.Type == EventPaired {
			paired++
		}
	}
	if paired != 1 || len(reqs) != 0 {
		t.Errorf("paired=%d (want 1), callback calls=%d (want 0)", paired, len(reqs))
	}
}
