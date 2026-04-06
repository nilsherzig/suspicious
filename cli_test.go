package main

import (
	"testing"
	"time"
)

func TestParseDecisionInput_Allow(t *testing.T) {
	cases := []struct{ input string }{
		{"j"}, {"ja"}, {"y"}, {"yes"}, {"J"}, {"JA"}, {""},
	}
	event := PromptEvent{ID: "x"}
	for _, tc := range cases {
		resp := parseDecisionInput(tc.input, event)
		if !resp.Allow {
			t.Errorf("input %q: expected allow, got deny", tc.input)
		}
		if resp.AutoAllowAll || resp.WhitelistChain {
			t.Errorf("input %q: unexpected flags set", tc.input)
		}
	}
}

func TestParseDecisionInput_Deny(t *testing.T) {
	cases := []struct{ input string }{
		{"n"}, {"nein"}, {"no"}, {"N"},
	}
	event := PromptEvent{ID: "x"}
	for _, tc := range cases {
		resp := parseDecisionInput(tc.input, event)
		if resp.Allow {
			t.Errorf("input %q: expected deny, got allow", tc.input)
		}
	}
}

func TestParseDecisionInput_AutoAllowAll(t *testing.T) {
	cases := []struct{ input string }{
		{"a"}, {"all"}, {"alle"}, {"A"},
	}
	event := PromptEvent{ID: "x"}
	for _, tc := range cases {
		resp := parseDecisionInput(tc.input, event)
		if !resp.Allow {
			t.Errorf("input %q: expected allow", tc.input)
		}
		if !resp.AutoAllowAll {
			t.Errorf("input %q: expected AutoAllowAll=true", tc.input)
		}
	}
}

func TestParseDecisionInput_WhitelistChain(t *testing.T) {
	event := PromptEvent{ID: "x"}
	resp := parseDecisionInput("w", event)
	if !resp.Allow {
		t.Error("whitelist: expected allow")
	}
	if !resp.WhitelistChain {
		t.Error("whitelist: expected WhitelistChain=true")
	}
}

func TestParseDecisionInput_PreservesID(t *testing.T) {
	event := PromptEvent{ID: "abc123"}
	resp := parseDecisionInput("j", event)
	if resp.ID != "abc123" {
		t.Errorf("ID not preserved: got %q", resp.ID)
	}
}

func TestFormatPromptEvent_ContainsPath(t *testing.T) {
	event := PromptEvent{
		ID:        "x",
		Pid:       42,
		Path:      "/etc/passwd",
		Action:    "OPEN",
		Timestamp: time.Now(),
		ProcessTree: []ProcessInfo{
			{Pid: 42, Name: "cat", Cmd: "cat /etc/passwd"},
		},
	}
	out := formatPromptEvent(event)
	if out == "" {
		t.Fatal("formatPromptEvent returned empty string")
	}
	for _, want := range []string{"/etc/passwd", "OPEN", "cat"} {
		found := false
		for i := 0; i+len(want) <= len(out); i++ {
			if out[i:i+len(want)] == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}
