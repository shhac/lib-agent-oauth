package oauth

import (
	"strings"
	"testing"
)

func TestPairingCodeFormatAndStability(t *testing.T) {
	p := NewPairing(NewMemStore())
	code, err := p.Code()
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if !strings.HasPrefix(code, pairingPrefix) {
		t.Errorf("code %q missing prefix %q", code, pairingPrefix)
	}
	// mcp- + five 5-char groups joined by hyphens.
	body := strings.TrimPrefix(code, pairingPrefix)
	groups := strings.Split(body, "-")
	if len(groups) != 5 {
		t.Errorf("code %q has %d groups, want 5", code, len(groups))
	}
	for _, g := range groups {
		if len(g) != 5 {
			t.Errorf("group %q is %d chars, want 5", g, len(g))
		}
	}
	// Stable across calls (persisted).
	if again, _ := p.Code(); again != code {
		t.Errorf("Code() not stable: %q then %q", code, again)
	}
}

func TestPairingVerify(t *testing.T) {
	p := NewPairing(NewMemStore())
	code, _ := p.Code()

	cases := map[string]bool{
		code:                                    true,  // exact
		strings.ToLower(code):                   true,  // case-insensitive
		strings.ReplaceAll(code, "-", ""):       true,  // hyphens optional
		strings.ReplaceAll(code, "-", " "):      true,  // spaces tolerated
		strings.TrimPrefix(code, pairingPrefix): true,  // prefix optional
		"mcp-00000-00000-00000-00000-00000":     false, // wrong code
		"":                                      false, // empty
		"not-a-code":                            false,
	}
	for input, want := range cases {
		_, got, err := p.VerifyPrincipal(input)
		if err != nil {
			t.Fatalf("Verify(%q): %v", input, err)
		}
		if got != want {
			t.Errorf("Verify(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestPairingConfusableChars(t *testing.T) {
	// Crockford folds O→0 and I/L→1; a human who types those should still match.
	// Build an input by replacing some canonical chars with their confusables.
	p := NewPairing(NewMemStore())
	code, _ := p.Code()
	confusable := strings.NewReplacer("0", "O", "1", "I").Replace(code)
	_, ok, err := p.VerifyPrincipal(confusable)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("confusable variant %q did not verify against %q", confusable, code)
	}
}

func TestPairingRotateInvalidatesOld(t *testing.T) {
	p := NewPairing(NewMemStore())
	old, _ := p.Code()
	rotated, err := p.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if rotated == old {
		t.Fatal("Rotate produced the same code")
	}
	if _, ok, _ := p.VerifyPrincipal(old); ok {
		t.Error("old code still verifies after rotate")
	}
	if _, ok, _ := p.VerifyPrincipal(rotated); !ok {
		t.Error("rotated code does not verify")
	}
}
