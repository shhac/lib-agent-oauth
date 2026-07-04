package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

const (
	maHost  = "https://hub.example"
	maSlack = "https://hub.example/slack/mcp"
	maLin   = "https://hub.example/lin/mcp"
)

// maHarness is a multi-audience host AS (EdDSA, two mounts) plus its HTTP test
// server, reusing the single-tool oauthHarness helpers for the OAuth flow.
func maHarness(t *testing.T) *oauthHarness {
	t.Helper()
	srv, err := New(Config{
		Store:      NewMemStore(),
		PublicURL:  maHost,
		Resources:  []string{maSlack, maLin},
		Asymmetric: true,
	})
	if err != nil {
		t.Fatalf("New multi-audience: %v", err)
	}
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &oauthHarness{srv: srv, http: ts, client: client}
}

// authorizeFor runs the approval POST with a specific resource and returns the
// redirect Location.
func (h *oauthHarness) authorizeFor(t *testing.T, clientID, pairingCode, resource string) *url.URL {
	t.Helper()
	form := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirect},
		"response_type":         {"code"},
		"code_challenge":        {challengeFor(testVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
		"scope":                 {"mcp"},
		"resource":              {resource},
		"pairing_code":          {pairingCode},
	}
	resp, err := h.client.PostForm(h.url(AuthorizePath), form)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302 (resource=%s)", resp.StatusCode, resource)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return loc
}

// The host mints a token whose audience is the requested mount, and only the
// delegate for THAT mount validates it — proving per-tool token isolation
// across one shared login/AS.
func TestMultiAudienceMintsPerMount(t *testing.T) {
	h := maHarness(t)
	shared, _ := h.srv.PairingCode()
	pub := h.srv.PublicKey()
	if pub == nil {
		t.Fatal("asymmetric host has no public key")
	}
	slackRS, _ := NewResourceServer(RSConfig{IssuerURL: maHost, Resource: maSlack, VerifyKey: pub})
	linRS, _ := NewResourceServer(RSConfig{IssuerURL: maHost, Resource: maLin, VerifyKey: pub})

	clientID := h.registerClient(t)

	// Authorize for the slack mount → token validates at slack, NOT at lin.
	slackCode := h.authorizeFor(t, clientID, shared, maSlack).Query().Get("code")
	slackTok, _ := h.exchange(t, clientID, slackCode)["access_token"].(string)
	if _, err := slackRS.verifier.Validate(slackTok); err != nil {
		t.Errorf("slack token rejected by slack mount: %v", err)
	}
	if _, err := linRS.verifier.Validate(slackTok); err == nil {
		t.Error("slack token wrongly validated at the lin mount — audiences not isolated")
	}

	// Authorize for the lin mount → token validates at lin, NOT at slack.
	linCode := h.authorizeFor(t, clientID, shared, maLin).Query().Get("code")
	linTok, _ := h.exchange(t, clientID, linCode)["access_token"].(string)
	if _, err := linRS.verifier.Validate(linTok); err != nil {
		t.Errorf("lin token rejected by lin mount: %v", err)
	}
	if _, err := slackRS.verifier.Validate(linTok); err == nil {
		t.Error("lin token wrongly validated at the slack mount")
	}
}

// A request for a resource the host doesn't serve is a redirectable
// invalid_target error — never a token for an unknown mount.
func TestMultiAudienceRejectsUnknownResource(t *testing.T) {
	h := maHarness(t)
	shared, _ := h.srv.PairingCode()
	clientID := h.registerClient(t)
	form := url.Values{
		"client_id": {clientID}, "redirect_uri": {testRedirect}, "response_type": {"code"},
		"code_challenge": {challengeFor(testVerifier)}, "code_challenge_method": {"S256"},
		"scope": {"mcp"}, "resource": {"https://hub.example/evil/mcp"}, "pairing_code": {shared},
	}
	resp, err := h.client.PostForm(h.url(AuthorizePath), form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 error redirect", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "invalid_target" {
		t.Errorf("error = %q, want invalid_target", loc.Query().Get("error"))
	}
}

// Each mount has its own RFC 9728 metadata document naming its own resource.
func TestMultiAudiencePerMountMetadata(t *testing.T) {
	h := maHarness(t)
	for path, wantResource := range map[string]string{
		ProtectedResourceMetadataPath + "/slack/mcp": maSlack,
		ProtectedResourceMetadataPath + "/lin/mcp":   maLin,
	} {
		doc := h.getJSON(t, path)
		if doc["resource"] != wantResource {
			t.Errorf("PRM at %s: resource = %v, want %s", path, doc["resource"], wantResource)
		}
		if as, _ := doc["authorization_servers"].([]any); len(as) != 1 || as[0] != maHost {
			t.Errorf("PRM at %s: authorization_servers = %v", path, doc["authorization_servers"])
		}
	}
}

// The refresh grant carries the resource, so a refreshed token keeps the same
// per-mount audience.
func TestMultiAudienceRefreshKeepsResource(t *testing.T) {
	h := maHarness(t)
	shared, _ := h.srv.PairingCode()
	pub := h.srv.PublicKey()
	slackRS, _ := NewResourceServer(RSConfig{IssuerURL: maHost, Resource: maSlack, VerifyKey: pub})
	clientID := h.registerClient(t)

	code := h.authorizeFor(t, clientID, shared, maSlack).Query().Get("code")
	refresh, _ := h.exchange(t, clientID, code)["refresh_token"].(string)

	resp := h.postForm(t, TokenPath, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d", resp.StatusCode)
	}
	var refreshed map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&refreshed); err != nil {
		t.Fatal(err)
	}
	tok, _ := refreshed["access_token"].(string)
	if _, err := slackRS.verifier.Validate(tok); err != nil {
		t.Errorf("refreshed token lost its slack audience: %v", err)
	}
}
