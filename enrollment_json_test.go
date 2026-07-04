package oauth

import (
	"encoding/json"
	"strings"
	"testing"
)

// The enrollment types are the wire protocol for out-of-process enrollment
// (agent-mcp-host reads a descriptor from `<tool> mcp schema` and drives the
// tool's callback over a subprocess bridge). These tests pin the JSON shape so
// a tag change that would silently break that bridge fails here instead.

func TestCredentialDescriptorJSONRoundTrip(t *testing.T) {
	in := CredentialDescriptor{
		Title: "Connect Widget",
		Intro: "Stored on the operator's machine.",
		Modes: []CredentialMode{{
			Key: "token", Label: "API token",
			Fields: []CredentialField{
				{Key: "token", Label: "API token", Help: "Find it in Settings", Snippet: "widget token", Secret: true},
				{Key: "region", Label: "Region", Optional: true},
			},
		}},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Snake-case keys the host parses.
	for _, want := range []string{`"title"`, `"intro"`, `"modes"`, `"key"`, `"label"`, `"fields"`, `"help"`, `"snippet"`, `"secret"`, `"optional"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("descriptor JSON missing %s: %s", want, raw)
		}
	}
	var out CredentialDescriptor
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Modes) != 1 || len(out.Modes[0].Fields) != 2 {
		t.Fatalf("round-trip shape lost: %+v", out)
	}
	if !out.Modes[0].Fields[0].Secret || out.Modes[0].Fields[0].Snippet != "widget token" {
		t.Errorf("secret/snippet not preserved: %+v", out.Modes[0].Fields[0])
	}
	if !out.Modes[0].Fields[1].Optional {
		t.Errorf("optional not preserved: %+v", out.Modes[0].Fields[1])
	}
}

func TestCredentialDescriptorOmitsEmpty(t *testing.T) {
	// A minimal field must not carry secret/optional/help/snippet noise, so the
	// host's rendered form defaults are clean.
	raw, err := json.Marshal(CredentialField{Key: "k", Label: "L"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, unwanted := range []string{`"secret"`, `"optional"`, `"help"`, `"snippet"`} {
		if strings.Contains(string(raw), unwanted) {
			t.Errorf("minimal field leaked %s: %s", unwanted, raw)
		}
	}
}

func TestEnrollRequestResultJSONRoundTrip(t *testing.T) {
	req := EnrollRequest{Principal: "alice", Mode: "token", Values: map[string]string{"token": "s3cr3t"}}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal req: %v", err)
	}
	var gotReq EnrollRequest
	if err := json.Unmarshal(raw, &gotReq); err != nil {
		t.Fatalf("unmarshal req: %v", err)
	}
	if gotReq.Principal != "alice" || gotReq.Values["token"] != "s3cr3t" {
		t.Errorf("req round-trip lost data: %+v", gotReq)
	}

	// A binding result and a choice result each survive the round trip.
	bindRaw, _ := json.Marshal(EnrollResult{Binding: map[string]string{"workspace": "acme"}})
	var bindOut EnrollResult
	if err := json.Unmarshal(bindRaw, &bindOut); err != nil || bindOut.Binding["workspace"] != "acme" || bindOut.Choice != nil {
		t.Errorf("binding result round-trip: %+v err=%v", bindOut, err)
	}
	choiceRaw, _ := json.Marshal(EnrollResult{Choice: &EnrollChoice{
		Prompt: "Which team?", Options: []ChoiceOption{{Value: "t1", Label: "Team One"}}, State: "opaque",
	}})
	var choiceOut EnrollResult
	if err := json.Unmarshal(choiceRaw, &choiceOut); err != nil {
		t.Fatalf("unmarshal choice: %v", err)
	}
	if choiceOut.Choice == nil || choiceOut.Choice.Prompt != "Which team?" || choiceOut.Choice.Options[0].Value != "t1" {
		t.Errorf("choice result round-trip: %+v", choiceOut.Choice)
	}
}

