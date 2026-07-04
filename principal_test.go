package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

// IsAnonymous is the operator/named-principal boundary every fail-closed gate
// routes through, so it must hold across the three shapes a grant can take.
func TestIsAnonymous(t *testing.T) {
	cases := []struct {
		name  string
		grant PrincipalGrant
		want  bool
	}{
		{"zero grant is the anonymous operator", PrincipalGrant{}, true},
		{"a named principal is not anonymous", PrincipalGrant{Name: "alice"}, false},
		{"a binding without a name is not anonymous", PrincipalGrant{Binding: map[string]string{"workspace": "acme"}}, false},
	}
	for _, tc := range cases {
		if got := tc.grant.IsAnonymous(); got != tc.want {
			t.Errorf("%s: IsAnonymous() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPrincipalPairingCodes(t *testing.T) {
	p := NewPairing(NewMemStore())

	code, err := p.AddPrincipal("alice", map[string]string{"workspace": "alice-acme"})
	if err != nil {
		t.Fatal(err)
	}
	if code == "" {
		t.Fatal("empty principal code")
	}

	grant, ok, err := p.VerifyPrincipal(code)
	if err != nil || !ok {
		t.Fatalf("verify alice: ok=%v err=%v", ok, err)
	}
	if grant.Name != "alice" || grant.Binding["workspace"] != "alice-acme" {
		t.Errorf("grant = %+v", grant)
	}

	// The legacy shared code still verifies — as the anonymous operator.
	legacy, err := p.Code()
	if err != nil {
		t.Fatal(err)
	}
	anon, ok, err := p.VerifyPrincipal(legacy)
	if err != nil || !ok {
		t.Fatalf("verify legacy: ok=%v err=%v", ok, err)
	}
	if anon.Name != "" {
		t.Errorf("legacy code should carry no principal, got %+v", anon)
	}

	if _, ok, _ := p.VerifyPrincipal("mcp-00000-00000-00000-00000-00000"); ok {
		t.Error("garbage code verified")
	}
}

func TestAddPrincipalRotatesExistingCode(t *testing.T) {
	p := NewPairing(NewMemStore())
	first, _ := p.AddPrincipal("alice", nil)
	second, err := p.AddPrincipal("alice", map[string]string{"workspace": "ws"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := p.VerifyPrincipal(first); ok {
		t.Error("re-adding a principal must rotate out its old code")
	}
	grant, ok, _ := p.VerifyPrincipal(second)
	if !ok || grant.Binding["workspace"] != "ws" {
		t.Errorf("rotated code grant = %+v ok=%v", grant, ok)
	}
}

// Re-adding without a binding must preserve the stored one — a code rotation
// that silently unbinds would lock a fail-closed principal out.
func TestAddPrincipalNilBindingPreservesExisting(t *testing.T) {
	p := NewPairing(NewMemStore())
	if _, err := p.AddPrincipal("alice", map[string]string{"workspace": "alice-acme"}); err != nil {
		t.Fatal(err)
	}
	code, err := p.AddPrincipal("alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, ok, _ := p.VerifyPrincipal(code)
	if !ok || grant.Binding["workspace"] != "alice-acme" {
		t.Errorf("nil-binding re-add lost the binding: grant = %+v ok=%v", grant, ok)
	}
}

func TestRotatePrincipal(t *testing.T) {
	p := NewPairing(NewMemStore())
	first, err := p.AddPrincipal("alice", map[string]string{"workspace": "alice-acme"})
	if err != nil {
		t.Fatal(err)
	}

	second, ok, err := p.RotatePrincipal("alice")
	if err != nil || !ok {
		t.Fatalf("rotate: ok=%v err=%v", ok, err)
	}
	if second == first {
		t.Error("rotate did not change the code")
	}
	if _, ok, _ := p.VerifyPrincipal(first); ok {
		t.Error("old code still verifies after rotate")
	}
	grant, ok, _ := p.VerifyPrincipal(second)
	if !ok || grant.Name != "alice" || grant.Binding["workspace"] != "alice-acme" {
		t.Errorf("rotated grant = %+v ok=%v (binding must survive rotation)", grant, ok)
	}

	// Rotation never creates.
	if _, ok, err := p.RotatePrincipal("nobody"); err != nil || ok {
		t.Errorf("rotating an unknown principal: ok=%v err=%v", ok, err)
	}
}

func TestPrincipalCodeReadBack(t *testing.T) {
	p := NewPairing(NewMemStore())
	minted, err := p.AddPrincipal("alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	code, ok, err := p.PrincipalCode("alice")
	if err != nil || !ok {
		t.Fatalf("read back: ok=%v err=%v", ok, err)
	}
	if code != minted {
		t.Errorf("PrincipalCode = %q, want the minted %q", code, minted)
	}
	if _, ok, err := p.PrincipalCode("nobody"); err != nil || ok {
		t.Errorf("unknown principal: ok=%v err=%v", ok, err)
	}
}

func TestFullFlowCarriesPrincipalIntoTokens(t *testing.T) {
	h := newHarness(t)
	code, err := h.srv.pairing.AddPrincipal("alice", map[string]string{"workspace": "alice-acme"})
	if err != nil {
		t.Fatal(err)
	}

	clientID := h.registerClient(t)
	authCode := h.authorize(t, clientID, code).Query().Get("code")
	if authCode == "" {
		t.Fatal("no authorization code")
	}
	tokens := h.exchange(t, clientID, authCode)
	access, _ := tokens["access_token"].(string)
	refresh, _ := tokens["refresh_token"].(string)

	v, err := h.srv.issuer.Validate(access)
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "alice" || v.Binding["workspace"] != "alice-acme" {
		t.Errorf("verified = %+v", v)
	}

	// Refresh preserves the principal and binding.
	rResp := h.postForm(t, TokenPath, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}})
	defer rResp.Body.Close()
	if rResp.StatusCode != http.StatusOK {
		t.Fatalf("refresh = %d", rResp.StatusCode)
	}
	var refreshed map[string]any
	if err := json.NewDecoder(rResp.Body).Decode(&refreshed); err != nil {
		t.Fatal(err)
	}
	v2, err := h.srv.issuer.Validate(refreshed["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if v2.Name != "alice" || v2.Binding["workspace"] != "alice-acme" {
		t.Errorf("refreshed verified = %+v", v2)
	}
}

func TestRemovePrincipalRevokesCodeAndRefreshTokens(t *testing.T) {
	store := NewMemStore()
	h := newHarnessWithStore(t, store)
	code, _ := h.srv.pairing.AddPrincipal("bob", nil)

	clientID := h.registerClient(t)
	authCode := h.authorize(t, clientID, code).Query().Get("code")
	tokens := h.exchange(t, clientID, authCode)
	refresh, _ := tokens["refresh_token"].(string)

	removed, err := NewPairing(store).RemovePrincipal("bob")
	if err != nil || !removed {
		t.Fatalf("remove: %v removed=%v", err, removed)
	}

	if _, ok, _ := h.srv.pairing.VerifyPrincipal(code); ok {
		t.Error("removed principal's code still verifies")
	}
	rResp := h.postForm(t, TokenPath, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}})
	defer rResp.Body.Close()
	if rResp.StatusCode == http.StatusOK {
		t.Error("removed principal's refresh token still exchanges")
	}
}

// Removing one principal must not touch the others' (or the anonymous
// operator's) refresh tokens — the revocation filter's blast radius.
func TestRemovePrincipalSparesOthers(t *testing.T) {
	store := NewMemStore()
	h := newHarnessWithStore(t, store)

	pairFor := func(code string) string {
		clientID := h.registerClient(t)
		authCode := h.authorize(t, clientID, code).Query().Get("code")
		tokens := h.exchange(t, clientID, authCode)
		refresh, _ := tokens["refresh_token"].(string)
		if refresh == "" {
			t.Fatal("no refresh token")
		}
		return refresh
	}

	aliceCode, _ := h.srv.pairing.AddPrincipal("alice", nil)
	bobCode, _ := h.srv.pairing.AddPrincipal("bob", nil)
	sharedCode, _ := h.srv.PairingCode()

	aliceRefresh := pairFor(aliceCode)
	bobRefresh := pairFor(bobCode)
	anonRefresh := pairFor(sharedCode)

	if _, err := NewPairing(store).RemovePrincipal("bob"); err != nil {
		t.Fatal(err)
	}

	exchangeStatus := func(refresh string) int {
		resp := h.postForm(t, TokenPath, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if exchangeStatus(bobRefresh) == http.StatusOK {
		t.Error("bob's refresh token survived his removal")
	}
	if exchangeStatus(aliceRefresh) != http.StatusOK {
		t.Error("alice's refresh token was collateral damage of bob's removal")
	}
	if exchangeStatus(anonRefresh) != http.StatusOK {
		t.Error("the anonymous operator's refresh token was collateral damage")
	}
}

// removeForPrincipal("") must be a no-op: the anonymous operator is not a
// removable principal, and "" must never act as a match-everything filter.
func TestRemoveForPrincipalEmptyNameIsNoop(t *testing.T) {
	store := NewMemStore()
	rs := newRefreshStore(store)
	tok, err := rs.issue("client-1", "mcp", PrincipalGrant{})
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.removeForPrincipal(""); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := rs.exchange(tok); !ok {
		t.Error("anonymous refresh grant deleted by empty-name removal")
	}
}

// With several principals registered, each code must resolve to exactly its
// own grant — never a sibling's.
func TestVerifyPrincipalResolvesAmongMany(t *testing.T) {
	p := NewPairing(NewMemStore())
	codes := map[string]string{}
	for _, name := range []string{"alice", "bob", "carol"} {
		code, err := p.AddPrincipal(name, map[string]string{"workspace": name + "-ws"})
		if err != nil {
			t.Fatal(err)
		}
		codes[name] = code
	}
	for name, code := range codes {
		grant, ok, err := p.VerifyPrincipal(code)
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", name, ok, err)
		}
		if grant.Name != name || grant.Binding["workspace"] != name+"-ws" {
			t.Errorf("%s's code resolved to %+v", name, grant)
		}
	}
	for _, input := range []string{"", "   "} {
		if _, ok, _ := p.VerifyPrincipal(input); ok {
			t.Errorf("blank input %q verified against the principal set", input)
		}
	}
}

// Concurrent AddPrincipal calls on one Pairing must all survive — the
// principals map store is a shared field precisely so its mutex serializes
// the load-modify-save cycles.
func TestConcurrentAddPrincipalsAllSurvive(t *testing.T) {
	p := NewPairing(NewMemStore())
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = p.AddPrincipal(fmt.Sprintf("p%02d", i), nil)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	principals, err := p.Principals()
	if err != nil {
		t.Fatal(err)
	}
	if len(principals) != n {
		t.Errorf("principals after %d concurrent adds = %d (lost updates)", n, len(principals))
	}
}
