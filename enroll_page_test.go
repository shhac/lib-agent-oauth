package oauth

import (
	"reflect"
	"testing"
)

func TestCollectModeFields(t *testing.T) {
	mode := CredentialMode{
		Key: "token",
		Fields: []CredentialField{
			{Key: "api_key", Label: "API key", Secret: true},
			{Key: "region", Label: "Region", Optional: true},
			{Key: "account", Label: "Account"},
		},
	}
	form := map[string]string{
		fieldInputName("token", "api_key"): "  sk-secret  ",
		fieldInputName("token", "region"):  "eu",
		fieldInputName("token", "account"): "",
	}

	values, nonSecret, missing := collectModeFields(mode, func(name string) string { return form[name] })

	// Every field's value is captured and trimmed, keyed by field key.
	if want := map[string]string{"api_key": "sk-secret", "region": "eu", "account": ""}; !reflect.DeepEqual(values, want) {
		t.Errorf("values = %v, want %v", values, want)
	}
	// Secret fields never enter the re-echo set.
	if want := map[string]string{"region": "eu", "account": ""}; !reflect.DeepEqual(nonSecret, want) {
		t.Errorf("nonSecret = %v, want %v", nonSecret, want)
	}
	// Only the required, empty, non-optional field is reported missing (by label).
	if want := []string{"Account"}; !reflect.DeepEqual(missing, want) {
		t.Errorf("missing = %v, want %v", missing, want)
	}
}

// A required secret left blank is still reported missing, and an all-satisfied
// submission reports none.
func TestCollectModeFieldsMissingCoverage(t *testing.T) {
	mode := CredentialMode{
		Key: "token",
		Fields: []CredentialField{
			{Key: "secret", Label: "Secret", Secret: true},
			{Key: "opt", Label: "Optional", Optional: true},
		},
	}

	_, _, missing := collectModeFields(mode, func(string) string { return "" })
	if want := []string{"Secret"}; !reflect.DeepEqual(missing, want) {
		t.Errorf("blank required secret: missing = %v, want %v", missing, want)
	}

	filled := map[string]string{fieldInputName("token", "secret"): "x"}
	if _, _, missing := collectModeFields(mode, func(n string) string { return filled[n] }); len(missing) != 0 {
		t.Errorf("all required satisfied: missing = %v, want none", missing)
	}
}
