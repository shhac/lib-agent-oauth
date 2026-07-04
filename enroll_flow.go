package oauth

import (
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

// enrollFlow carries the request-scoped invariants of one enrollment
// interaction — the values that never change between the form, the callback
// rounds, and the finish — so the flow's methods take only what actually
// varies (view, mode, result). Built once in divertToEnrollment.
type enrollFlow struct {
	s           *Server
	w           http.ResponseWriter
	r           *http.Request
	client      Client
	p           authParams
	principal   PrincipalGrant
	pairingCode string
	e           *Enrollment
}

// renderPage shows the descriptor-driven enrollment form.
func (f *enrollFlow) renderPage(view enrollView) {
	d := f.e.Descriptor
	selected := view.Mode
	if selected == "" {
		selected = d.Modes[0].Key
	}
	modes := enrollModeViews(d, selected, view.Values)

	hidden := f.p.hiddenFieldsWithCode(f.pairingCode)
	hidden["enroll"] = "1"
	f.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = enrollTmpl.Execute(f.w, map[string]any{
		"Action":     AuthorizePath,
		"Title":      d.Title,
		"Intro":      d.Intro,
		"Principal":  f.principal.Name,
		"ClientName": f.client.Name,
		"Error":      view.Err,
		"SingleMode": len(modes) == 1,
		"Modes":      modes,
		"Hidden":     hidden,
	})
}

// submittedMode resolves the mode this enrollment POST addresses — the shared
// prelude of both rounds. ok=false means the form was already re-rendered.
// The pairing code was already re-verified by authorizeSubmit before either
// round is reached.
func (f *enrollFlow) submittedMode() (CredentialMode, bool) {
	mode, ok := f.e.mode(f.r.PostForm.Get("enroll_mode"))
	if !ok {
		f.renderPage(enrollView{Err: "Pick how you want to authenticate."})
	}
	return mode, ok
}

// submitFields processes the first enrollment round: required-field check,
// callback with the submitted values, then finish (persist or divert to a
// choice round).
func (f *enrollFlow) submitFields() {
	mode, ok := f.submittedMode()
	if !ok {
		return
	}
	values, nonSecret, missing := collectModeFields(mode, f.r.PostForm.Get)
	view := enrollView{Mode: mode.Key, Values: nonSecret}
	if len(missing) > 0 {
		view.Err = "Required: " + strings.Join(missing, ", ")
		f.renderPage(view)
		return
	}

	res, err := f.e.Enroll(f.r.Context(), EnrollRequest{
		Principal: f.principal.Name,
		Mode:      mode.Key,
		Values:    values,
	})
	f.finish(mode.Key, res, err, view)
}

// submitChoice processes the follow-up round after an EnrollResult.Choice:
// the selection (plus the callback's opaque State) rides instead of field
// values — the callback already holds whatever it needs from the first round.
func (f *enrollFlow) submitChoice() {
	mode, ok := f.submittedMode()
	if !ok {
		return
	}
	choice := f.r.PostForm.Get("enroll_choice")
	if choice == "" {
		f.renderPage(enrollView{Mode: mode.Key, Err: "No option was selected — start again."})
		return
	}
	res, err := f.e.Enroll(f.r.Context(), EnrollRequest{
		Principal: f.principal.Name,
		Mode:      mode.Key,
		Choice:    choice,
		State:     f.r.PostForm.Get("enroll_state"),
	})
	f.finish(mode.Key, res, err, enrollView{Mode: mode.Key})
}

// finish routes an EnrollResult: error → re-render the form (secrets
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
func (f *enrollFlow) finish(modeKey string, res EnrollResult, err error, view enrollView) {
	if err != nil {
		view.Err = err.Error()
		f.renderPage(view)
		return
	}
	if res.Choice != nil {
		if len(res.Choice.Options) == 0 {
			f.s.authorizeErrorPage(f.w, "internal error: enrollment offered an empty choice")
			return
		}
		f.s.renderEnrollChoice(f.w, f.client, f.p, f.pairingCode, f.principal, modeKey, res.Choice, "")
		return
	}
	if len(res.Binding) == 0 {
		f.s.authorizeErrorPage(f.w, "internal error: enrollment returned no binding")
		return
	}
	// Merge, not replace: in host mode the returned binding is one tool's
	// namespaced slice of the principal's record — enrolling for slack must
	// not wipe the lin keys enrolled last week. Same-key overwrite keeps
	// single-tool re-enrollment idempotent as before.
	merged, found, err := f.s.pairing.MergePrincipalBinding(f.principal.Name, res.Binding)
	if err != nil || !found {
		f.s.authorizeErrorPage(f.w, "internal error storing the credential binding")
		return
	}
	f.s.event(Event{Type: EventEnrolled, Principal: f.principal.Name, Client: f.client.Name,
		Resource: f.s.eventResource(f.p)})
	// The FRESH merged grant, deliberately not f.principal: the carried
	// principal still holds the pre-enrollment (possibly empty) binding.
	f.s.issueAndRedirect(f.w, f.r, f.client, f.p, PrincipalGrant{Name: f.principal.Name, Binding: merged})
}
