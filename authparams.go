package oauth

import "net/url"

// authParams are the authorization-request parameters, shared by the GET form
// and the POST submission (the form round-trips them as hidden fields).
type authParams struct {
	clientID            string
	redirectURI         string
	state               string
	scope               string
	resource            string
	codeChallenge       string
	codeChallengeMethod string
	responseType        string
}

func parseAuthParams(v url.Values) authParams {
	return authParams{
		clientID:            v.Get("client_id"),
		redirectURI:         v.Get("redirect_uri"),
		state:               v.Get("state"),
		scope:               v.Get("scope"),
		resource:            v.Get("resource"),
		codeChallenge:       v.Get("code_challenge"),
		codeChallengeMethod: v.Get("code_challenge_method"),
		responseType:        v.Get("response_type"),
	}
}

// hiddenFields is the authorization request as a hidden-input set, so a form
// round-trips it unchanged.
func (p authParams) hiddenFields() map[string]string {
	return map[string]string{
		"client_id":             p.clientID,
		"redirect_uri":          p.redirectURI,
		"response_type":         p.responseType,
		"code_challenge":        p.codeChallenge,
		"code_challenge_method": p.codeChallengeMethod,
		"state":                 p.state,
		"scope":                 p.scope,
		"resource":              p.resource,
	}
}

// hiddenFieldsWithCode extends hiddenFields with the already-verified pairing
// code — the round-trip set the post-code forms (enrollment, chooser) share.
// Each form layers its own flow markers (enroll, choose, enroll_choice_round)
// on top; the shared builder carries none, so no caller has to tear one back
// off.
func (p authParams) hiddenFieldsWithCode(pairingCode string) map[string]string {
	h := p.hiddenFields()
	h["pairing_code"] = pairingCode
	return h
}
