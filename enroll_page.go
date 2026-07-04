package oauth

import (
	"html/template"
	"net/http"
	"strings"
)

// The enrollment page keeps the authorize flow's statelessness: the OAuth
// request params and the (already-verified) pairing code round-trip as hidden
// fields, and the code is re-verified on the enrollment POST before anything
// else happens. No auth code exists until the callback has returned a binding,
// so an abandoned or failing enrollment leaves the principal unbound — which
// fail-closed mode turns into a refusal, never a fallback identity.

// enrollView is the re-render state of the enrollment form: the error to
// show, the mode that was selected, and the submitted values to preserve —
// secret fields are never included, so they can never be re-echoed.
type enrollView struct {
	Err    string
	Mode   string
	Values map[string]string
}

// renderEnrollPage shows the descriptor-driven enrollment form for e — the
// enrollment divertToEnrollment resolved for this request's resource.
func (s *Server) renderEnrollPage(w http.ResponseWriter, client Client, p authParams, pairingCode string, principal PrincipalGrant, view enrollView, e *Enrollment) {
	d := e.Descriptor
	selected := view.Mode
	if selected == "" {
		selected = d.Modes[0].Key
	}
	type fieldView struct {
		Name, Label, Help, Snippet, Value string
		Secret, Optional                  bool
	}
	type modeView struct {
		Key, Label string
		Selected   bool
		Fields     []fieldView
	}
	modes := make([]modeView, 0, len(d.Modes))
	for _, m := range d.Modes {
		mv := modeView{Key: m.Key, Label: m.Label, Selected: m.Key == selected}
		for _, f := range m.Fields {
			// Input names are namespaced per mode: with several modes on one
			// page, un-namespaced keys shared between modes (both having
			// "password") would shadow each other in the POST.
			fv := fieldView{Name: fieldInputName(m.Key, f.Key), Label: f.Label, Help: f.Help, Snippet: f.Snippet, Secret: f.Secret, Optional: f.Optional}
			if !f.Secret {
				fv.Value = view.Values[f.Key]
			}
			mv.Fields = append(mv.Fields, fv)
		}
		modes = append(modes, mv)
	}

	hidden := p.hiddenFieldsWithCode(pairingCode)
	hidden["enroll"] = "1"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = enrollTmpl.Execute(w, map[string]any{
		"Action":     AuthorizePath,
		"Title":      d.Title,
		"Intro":      d.Intro,
		"Principal":  principal.Name,
		"ClientName": client.Name,
		"Error":      view.Err,
		"SingleMode": len(modes) == 1,
		"Modes":      modes,
		"Hidden":     hidden,
	})
}

// fieldInputName is the HTML input name for a descriptor field.
func fieldInputName(modeKey, fieldKey string) string {
	return "field_" + modeKey + "_" + fieldKey
}

// collectModeFields reads one mode's submitted fields (via get, over the
// per-mode namespaced input names) into three views: values keyed by field key
// for the callback, the non-secret subset safe to re-echo into a re-rendered
// form, and the labels of any required field left blank. Pure — no request or
// response state — so the required-field logic is unit-testable directly.
func collectModeFields(mode CredentialMode, get func(name string) string) (values, nonSecret map[string]string, missing []string) {
	values = make(map[string]string, len(mode.Fields))
	nonSecret = map[string]string{}
	for _, f := range mode.Fields {
		v := strings.TrimSpace(get(fieldInputName(mode.Key, f.Key)))
		values[f.Key] = v
		if !f.Secret {
			nonSecret[f.Key] = v
		}
		if v == "" && !f.Optional {
			missing = append(missing, f.Label)
		}
	}
	return values, nonSecret, missing
}

// enrollSubmit processes the enrollment POST: required-field check, callback,
// binding persistence, then the standard code issue + redirect. The pairing
// code was already re-verified by authorizeSubmit before this is reached.
// A follow-up POST after an EnrollResult.Choice carries the selection instead
// of field values — the callback already holds (or encoded in State) whatever
// it needs from the first round.
func (s *Server) enrollSubmit(w http.ResponseWriter, r *http.Request, client Client, p authParams, principal PrincipalGrant, e *Enrollment) {
	pairingCode := r.PostForm.Get("pairing_code")
	mode, ok := e.mode(r.PostForm.Get("enroll_mode"))
	if !ok {
		s.renderEnrollPage(w, client, p, pairingCode, principal, enrollView{Err: "Pick how you want to authenticate."}, e)
		return
	}

	if r.PostForm.Get("enroll_choice_round") == "1" {
		choice := r.PostForm.Get("enroll_choice")
		if choice == "" {
			s.renderEnrollPage(w, client, p, pairingCode, principal,
				enrollView{Mode: mode.Key, Err: "No option was selected — start again."}, e)
			return
		}
		res, err := e.Enroll(r.Context(), EnrollRequest{
			Principal: principal.Name,
			Mode:      mode.Key,
			Choice:    choice,
			State:     r.PostForm.Get("enroll_state"),
		})
		s.finishEnroll(w, r, client, p, pairingCode, principal, mode.Key, res, err, enrollView{Mode: mode.Key}, e)
		return
	}

	values, nonSecret, missing := collectModeFields(mode, r.PostForm.Get)
	view := enrollView{Mode: mode.Key, Values: nonSecret}
	if len(missing) > 0 {
		view.Err = "Required: " + strings.Join(missing, ", ")
		s.renderEnrollPage(w, client, p, pairingCode, principal, view, e)
		return
	}

	res, err := e.Enroll(r.Context(), EnrollRequest{
		Principal: principal.Name,
		Mode:      mode.Key,
		Values:    values,
	})
	s.finishEnroll(w, r, client, p, pairingCode, principal, mode.Key, res, err, view, e)
}

// finishEnroll routes an EnrollResult: error → re-render the form (secrets
// cleared); Choice → render the chooser for a follow-up round; Binding →
// persist and finish the OAuth flow.
//
// Premise: an enrollment binding is singleton-valued, never a set. Enrollment
// bootstraps one identity (see design-docs/enrollment.md), so the persisted
// binding goes straight into the issued token here without a chooser pass. A
// callback that returned a comma-separated set would ride comma-joined into the
// token rather than being narrowed — the allowed-set chooser is an
// operator-provisioning affordance (`pair add --bind k=a,b`), not an
// enrollment one.
func (s *Server) finishEnroll(w http.ResponseWriter, r *http.Request, client Client, p authParams, pairingCode string, principal PrincipalGrant, modeKey string, res EnrollResult, err error, view enrollView, e *Enrollment) {
	if err != nil {
		view.Err = err.Error()
		s.renderEnrollPage(w, client, p, pairingCode, principal, view, e)
		return
	}
	if res.Choice != nil {
		if len(res.Choice.Options) == 0 {
			s.authorizeErrorPage(w, "internal error: enrollment offered an empty choice")
			return
		}
		s.renderEnrollChoice(w, client, p, pairingCode, principal, modeKey, res.Choice, "")
		return
	}
	if len(res.Binding) == 0 {
		s.authorizeErrorPage(w, "internal error: enrollment returned no binding")
		return
	}
	// Merge, not replace: in host mode the returned binding is one tool's
	// namespaced slice of the principal's record — enrolling for slack must
	// not wipe the lin keys enrolled last week. Same-key overwrite keeps
	// single-tool re-enrollment idempotent as before.
	merged, found, err := s.pairing.MergePrincipalBinding(principal.Name, res.Binding)
	if err != nil || !found {
		s.authorizeErrorPage(w, "internal error storing the credential binding")
		return
	}
	s.issueAndRedirect(w, r, client, p, PrincipalGrant{Name: principal.Name, Binding: merged})
}

var enrollTmpl = template.Must(template.New("enroll").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .Title}}{{.Title}}{{else}}Set up credentials{{end}}</title>
<style>
` + basePageCSS + `
input[type=text],input[type=password]{font-size:1rem;padding:.55rem;width:100%;box-sizing:border-box;margin-top:.25rem}
fieldset{border:1px solid #ccc;border-radius:.4rem;margin-top:1rem;padding:.75rem 1rem}
label.field{display:block;margin-top:.75rem}
.err{color:#b00020;border:1px solid #b00020;border-radius:.4rem;padding:.5rem .75rem}
.help{color:#555;font-size:.85rem;margin:.15rem 0 0}
.snippet{display:flex;align-items:stretch;gap:.4rem;margin:.4rem 0 0}
.snippet pre{flex:1;margin:0;padding:.5rem .6rem;background:#f4f4f4;border:1px solid #ddd;border-radius:.4rem;font-size:.8rem;overflow-x:auto;user-select:all;white-space:pre-wrap;word-break:break-all}
.snippet button{font-size:.8rem;padding:0 .7rem;cursor:pointer;border:1px solid #ccc;border-radius:.4rem;background:#fff}
</style></head><body>
<h1>{{if .Title}}{{.Title}}{{else}}Set up credentials{{end}}</h1>
<p class="muted">Hi {{.Principal}} — one-time setup{{if .ClientName}} to finish connecting “{{.ClientName}}”{{end}}.</p>
{{if .Intro}}<p class="muted">{{.Intro}}</p>{{end}}
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}" autocomplete="off">
{{$single := .SingleMode}}
{{range .Modes}}
  <fieldset>
    {{if not $single}}<label><input type="radio" name="enroll_mode" value="{{.Key}}"{{if .Selected}} checked{{end}}> {{.Label}}</label>
    {{else}}<input type="hidden" name="enroll_mode" value="{{.Key}}">{{if .Label}}<legend>{{.Label}}</legend>{{end}}{{end}}
    {{range .Fields}}
    <label class="field">{{.Label}}{{if .Optional}} <span class="muted">(optional)</span>{{end}}
      <input type="{{if .Secret}}password{{else}}text{{end}}" name="{{.Name}}" value="{{.Value}}" autocomplete="off">
    </label>
    {{if .Help}}<p class="help">{{.Help}}</p>{{end}}
    {{if .Snippet}}<div class="snippet"><pre>{{.Snippet}}</pre><button type="button" onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent)">Copy</button></div>{{end}}
    {{end}}
  </fieldset>
{{end}}
  {{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
  <button type="submit">Verify &amp; continue</button>
</form>
</body></html>`))
