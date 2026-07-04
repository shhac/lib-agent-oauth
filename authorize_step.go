package oauth

import "net/url"

// authorizeStep names which round of the authorize POST flow a request is.
// The flow is a small state machine whose state rides in hidden form markers
// (`enroll`, `enroll_choice_round`, `choose`); classifyStep is the ONE place
// those markers are interpreted, so routing — and anything gated on "is this
// the initial approval?", like the paired event — can never drift into
// scattered negations. A new sub-step is a new constant plus a case here, not
// another exception at every existing site.
type authorizeStep int

const (
	// stepInitialApproval is the first POST: the person just proved identity
	// (pairing code or session) on the approval page. The pairing moment.
	stepInitialApproval authorizeStep = iota
	// stepEnrollFields is an enrollment-form submission (credential values).
	stepEnrollFields
	// stepEnrollChoice is the follow-up round after an EnrollResult.Choice.
	stepEnrollChoice
	// stepBindingChoice is the allowed-set chooser submission.
	stepBindingChoice
)

// classifyStep derives the flow step from the POSTed form. Precedence mirrors
// the pre-classifier dispatch order exactly: an `enroll` marker wins over
// `choose` (a forged POST carrying both is an enrollment round), and
// `enroll_choice_round` counts only inside an enrollment round (forged
// standalone, it classifies as the initial approval, as it always did).
func classifyStep(form url.Values) authorizeStep {
	switch {
	case form.Get("enroll") == "1" && form.Get("enroll_choice_round") == "1":
		return stepEnrollChoice
	case form.Get("enroll") == "1":
		return stepEnrollFields
	case form.Get("choose") == "1":
		return stepBindingChoice
	default:
		return stepInitialApproval
	}
}
