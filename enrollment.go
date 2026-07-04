package oauth

import (
	"context"
	"fmt"
)

// This file is the credential-enrollment seam (design-docs/enrollment.md):
// the lib owns the browser flow and persists only the returned non-secret
// binding; the embedding CLI owns the field vocabulary, validation, and
// custody of the submitted secrets. Secrets cross this boundary once, in
// memory, in one direction.

// CredentialField is one input on the enrollment form.
type CredentialField struct {
	// Key is the callback map key (and, namespaced, the form input name).
	Key string
	// Label is the human-facing field label.
	Label string
	// Help is a one-liner rendered under the field — where to find the value.
	Help string
	// Snippet, when non-empty, renders below Help as a distinct monospace code
	// block with a copy button — for a command or console one-liner the human
	// runs to obtain the value. Kept out of Help so it reads as "copy this",
	// not prose. The copy button is progressive enhancement; the block is
	// selectable without JS.
	Snippet string
	// Secret renders a password input; the value is never logged and never
	// re-echoed into a re-rendered form.
	Secret bool
	// Optional fields may be left empty; all others are required before the
	// callback is invoked.
	Optional bool
}

// CredentialMode is one mutually-exclusive way of authenticating, with its
// own flat field list. Prefer collapsing modes behind a classifier when the
// secret's own shape identifies it (key prefixes); declare several modes only
// when the field sets genuinely differ. A single mode renders no selector.
type CredentialMode struct {
	Key    string
	Label  string
	Fields []CredentialField
}

// CredentialDescriptor declares what the enrollment form asks for. It is
// static, non-secret data; the lib renders it verbatim and understands none
// of it.
type CredentialDescriptor struct {
	Title string
	Intro string
	Modes []CredentialMode
}

// EnrollRequest carries one form submission to the callback.
type EnrollRequest struct {
	// Principal is the verified principal name — the callback must scope every
	// write to it; there is no input through which a caller can name another
	// principal's credentials.
	Principal string
	// Mode is the key of the chosen CredentialMode.
	Mode string
	// Values holds the submitted fields for that mode, keyed by field Key.
	Values map[string]string
	// Choice and State are set only on the follow-up call after the callback
	// returned an EnrollChoice; Values is empty on that call. Choice is
	// untrusted input — the callback must re-validate it against its own data.
	Choice string
	State  string
}

// ChoiceOption is one selectable option in an EnrollChoice.
type ChoiceOption struct {
	Value string
	Label string
}

// EnrollChoice asks the human to pick among options the callback could only
// learn by using the just-validated credential (e.g. which team a verified
// token reaches). The follow-up call carries the selection in
// EnrollRequest.Choice. Chains are allowed: a follow-up may return another
// Choice.
type EnrollChoice struct {
	Prompt  string
	Options []ChoiceOption
	// State is opaque callback state, round-tripped into the follow-up
	// EnrollRequest. It is rendered into the page as a hidden field, so it
	// must never contain secrets.
	State string
}

// EnrollResult is what the callback returns: a Binding (done — persisted on
// the pairing record, after which the OAuth flow resumes) or a Choice (the
// chooser page renders the options and the callback is called again).
type EnrollResult struct {
	Binding map[string]string
	Choice  *EnrollChoice
}

// EnrollFunc validates and stores the submitted credentials, returning the
// binding to persist. An error re-renders the form with err's message; secret
// fields come back empty. The callback must be idempotent — re-enrollment
// overwrites the same slot.
type EnrollFunc func(ctx context.Context, req EnrollRequest) (EnrollResult, error)

// Enrollment pairs the descriptor with its callback.
type Enrollment struct {
	Descriptor CredentialDescriptor
	Enroll     EnrollFunc
}

// validate checks the descriptor is renderable: at least one mode, unique
// non-empty mode and field keys, and a callback to hand submissions to.
func (e *Enrollment) validate() error {
	if e.Enroll == nil {
		return fmt.Errorf("oauth: enrollment: Enroll callback is required")
	}
	if len(e.Descriptor.Modes) == 0 {
		return fmt.Errorf("oauth: enrollment: descriptor needs at least one mode")
	}
	modeKeys := map[string]bool{}
	for _, m := range e.Descriptor.Modes {
		if m.Key == "" {
			return fmt.Errorf("oauth: enrollment: mode with empty key")
		}
		if modeKeys[m.Key] {
			return fmt.Errorf("oauth: enrollment: duplicate mode key %q", m.Key)
		}
		modeKeys[m.Key] = true
		if len(m.Fields) == 0 {
			return fmt.Errorf("oauth: enrollment: mode %q has no fields", m.Key)
		}
		fieldKeys := map[string]bool{}
		for _, f := range m.Fields {
			if f.Key == "" {
				return fmt.Errorf("oauth: enrollment: mode %q has a field with an empty key", m.Key)
			}
			if fieldKeys[f.Key] {
				return fmt.Errorf("oauth: enrollment: mode %q duplicates field key %q", m.Key, f.Key)
			}
			fieldKeys[f.Key] = true
		}
	}
	return nil
}

// mode returns the descriptor mode for key. With exactly one mode an empty
// key selects it (no selector is rendered in that case).
func (e *Enrollment) mode(key string) (CredentialMode, bool) {
	if key == "" && len(e.Descriptor.Modes) == 1 {
		return e.Descriptor.Modes[0], true
	}
	for _, m := range e.Descriptor.Modes {
		if m.Key == key {
			return m, true
		}
	}
	return CredentialMode{}, false
}
