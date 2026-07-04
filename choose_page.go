package oauth

import (
	"html/template"
	"net/http"
	"sort"
	"strings"
)

// The chooser page serves two flows that share one screen:
//
//  1. Allowed-set bindings: a principal's stored binding value may be a
//     comma-separated set (`pair add alice --bind workspace=acme,personal`).
//     At authorize time the person picks one value per set-valued key; the
//     CHOSEN singleton rides in the token claims, the record keeps the set.
//     The server validates choices against the stored set — the store is the
//     authority, so a forged POST cannot select an unoffered value.
//
//  2. Enrollment EnrollResult.Choice: options the CLI could only learn by
//     using the just-validated credential (vercel: which team). Here the
//     options round-trip through the form, so the CALLBACK is the authority:
//     it must re-validate the submitted Choice, and State must never carry
//     secrets (it is rendered into the page).
//
// Both flows re-verify the pairing code on every POST — same statelessness
// as the rest of the authorize flow.

// bindingSeparator splits a set-valued binding value. By convention binding
// values do not contain commas; a CLI that needs literal commas cannot use
// allowed sets.
const bindingSeparator = ","

// bindingSet parses one binding value as a set, reporting whether it holds
// more than one member.
func bindingSet(value string) ([]string, bool) {
	if !strings.Contains(value, bindingSeparator) {
		return nil, false
	}
	var members []string
	for _, m := range strings.Split(value, bindingSeparator) {
		if m = strings.TrimSpace(m); m != "" {
			members = append(members, m)
		}
	}
	return members, len(members) > 1
}

// setValuedKeys returns the binding keys holding sets, sorted for a stable
// page and stable tests.
func setValuedKeys(binding map[string]string) []string {
	var keys []string
	for k, v := range binding {
		if _, ok := bindingSet(v); ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// resolveBindingChoices validates one submitted choice per set-valued key
// against the STORED binding and returns the resolved singleton binding.
// A missing or unoffered choice reports false.
func resolveBindingChoices(binding map[string]string, choice func(key string) string) (map[string]string, bool) {
	resolved := make(map[string]string, len(binding))
	for k, v := range binding {
		members, isSet := bindingSet(v)
		if !isSet {
			resolved[k] = v
			continue
		}
		chosen := choice(k)
		valid := false
		for _, m := range members {
			if m == chosen {
				valid = true
				break
			}
		}
		if !valid {
			return nil, false
		}
		resolved[k] = chosen
	}
	return resolved, true
}

// chooseView is the data for one rendered chooser: either the binding-set
// selects (Sets) or an enrollment Choice (Prompt/Options + State).
type chooseView struct {
	Err string
	// Binding-set flow:
	Sets []chooseSet
	// Enrollment-Choice flow:
	Prompt  string
	Options []ChoiceOption
	State   string
	Mode    string
}

type chooseSet struct {
	Key     string
	Options []string
}

// renderBindingChooser shows one select per set-valued binding key.
func (s *Server) renderBindingChooser(w http.ResponseWriter, client Client, p authParams, pairingCode string, principal PrincipalGrant, errMsg string) {
	var sets []chooseSet
	for _, k := range setValuedKeys(principal.Binding) {
		members, _ := bindingSet(principal.Binding[k])
		sets = append(sets, chooseSet{Key: k, Options: members})
	}
	s.renderChooser(w, client, p, pairingCode, principal, chooseView{Err: errMsg, Sets: sets}, map[string]string{"choose": "1"})
}

// renderEnrollChoice shows the callback-provided options after a Choice
// result. The mode and opaque state ride along so the follow-up call can
// reach the callback with context intact.
func (s *Server) renderEnrollChoice(w http.ResponseWriter, client Client, p authParams, pairingCode string, principal PrincipalGrant, mode string, choice *EnrollChoice, errMsg string) {
	s.renderChooser(w, client, p, pairingCode, principal, chooseView{
		Err:     errMsg,
		Prompt:  choice.Prompt,
		Options: choice.Options,
		State:   choice.State,
		Mode:    mode,
	}, map[string]string{"enroll": "1", "enroll_choice_round": "1"})
}

func (s *Server) renderChooser(w http.ResponseWriter, client Client, p authParams, pairingCode string, principal PrincipalGrant, view chooseView, markers map[string]string) {
	hidden := p.hiddenFieldsWithCode(pairingCode)
	for k, v := range markers {
		hidden[k] = v
	}
	if view.State != "" {
		hidden["enroll_state"] = view.State
	}
	if view.Mode != "" {
		hidden["enroll_mode"] = view.Mode
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = chooseTmpl.Execute(w, map[string]any{
		"Action":     AuthorizePath,
		"ClientName": client.Name,
		"Principal":  principal.Name,
		"View":       view,
		"Hidden":     hidden,
	})
}

var chooseTmpl = template.Must(template.New("choose").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Choose</title>
<style>
` + basePageCSS + `
label.opt{display:block;margin:.4rem 0}
.err{color:#b00020;border:1px solid #b00020;border-radius:.4rem;padding:.5rem .75rem}
fieldset{border:1px solid #ccc;border-radius:.4rem;margin-top:1rem;padding:.75rem 1rem}
</style></head><body>
<h1>Hi {{.Principal}} — one more choice</h1>
{{if .View.Err}}<p class="err">{{.View.Err}}</p>{{end}}
<form method="post" action="{{.Action}}">
{{if .View.Sets}}
  {{range .View.Sets}}
  <fieldset><legend>{{.Key}}</legend>
    {{$key := .Key}}
    {{range $i, $opt := .Options}}
    <label class="opt"><input type="radio" name="choice_{{$key}}" value="{{$opt}}"{{if eq $i 0}} checked{{end}}> {{$opt}}</label>
    {{end}}
  </fieldset>
  {{end}}
  <p class="muted">Only values your pairing grants are listed; this choice applies to this connection.</p>
{{else}}
  <fieldset>{{if .View.Prompt}}<legend>{{.View.Prompt}}</legend>{{end}}
    {{range $i, $opt := .View.Options}}
    <label class="opt"><input type="radio" name="enroll_choice" value="{{$opt.Value}}"{{if eq $i 0}} checked{{end}}> {{$opt.Label}}</label>
    {{end}}
  </fieldset>
{{end}}
  {{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
  <button type="submit">Continue</button>
</form>
</body></html>`))
