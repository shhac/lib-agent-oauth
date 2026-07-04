package oauth

import "strings"

// The pure view-model half of the enrollment form: input naming, the
// template's mode/field views, and submitted-field collection — no request or
// response state, mirrored read/write sides (enrollModeViews renders what
// collectModeFields later reads back).

func fieldInputName(modeKey, fieldKey string) string {
	return "field_" + modeKey + "_" + fieldKey
}

// enrollFieldView is one rendered enrollment input: descriptor data plus the
// per-mode namespaced input name and any re-echoed (non-secret) value.
type enrollFieldView struct {
	Name, Label, Help, Snippet, Value string
	Secret, Optional                  bool
}

// enrollModeView is one rendered authentication mode: its fields plus whether
// it is the selected (open) mode.
type enrollModeView struct {
	Key, Label string
	Selected   bool
	Fields     []enrollFieldView
}

// enrollModeViews builds the per-mode view data the enrollment template renders
// from a descriptor: field input names are namespaced per mode (so a key shared
// across modes doesn't shadow itself in the POST), non-secret values are
// re-echoed from a prior submission, and the mode matching selected is marked
// open. Pure — no request/response state — the render-side mirror of
// collectModeFields.
func enrollModeViews(d CredentialDescriptor, selected string, values map[string]string) []enrollModeView {
	modes := make([]enrollModeView, 0, len(d.Modes))
	for _, m := range d.Modes {
		mv := enrollModeView{Key: m.Key, Label: m.Label, Selected: m.Key == selected}
		for _, f := range m.Fields {
			fv := enrollFieldView{Name: fieldInputName(m.Key, f.Key), Label: f.Label, Help: f.Help, Snippet: f.Snippet, Secret: f.Secret, Optional: f.Optional}
			if !f.Secret {
				fv.Value = values[f.Key]
			}
			mv.Fields = append(mv.Fields, fv)
		}
		modes = append(modes, mv)
	}
	return modes
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

// submit processes the enrollment POST: required-field check, callback,
// binding persistence, then the standard code issue + redirect. The pairing
// code was already re-verified by authorizeSubmit before this is reached.
// A follow-up POST after an EnrollResult.Choice carries the selection instead
// of field values — the callback already holds (or encoded in State) whatever
// it needs from the first round.
