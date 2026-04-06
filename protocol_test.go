package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPromptEvent_JSONRoundtrip(t *testing.T) {
	event := PromptEvent{
		ID:   "abc123",
		Pid:  1234,
		Path: "/etc/passwd",
		ProcessTree: []ProcessInfo{
			{Pid: 1234, Name: "cat", Cmd: "cat /etc/passwd"},
			{Pid: 999, Name: "zsh", Cmd: "zsh"},
		},
		Action:    "OPEN",
		Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got PromptEvent
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ID != event.ID {
		t.Errorf("ID: got %q, want %q", got.ID, event.ID)
	}
	if got.Pid != event.Pid {
		t.Errorf("Pid: got %d, want %d", got.Pid, event.Pid)
	}
	if got.Path != event.Path {
		t.Errorf("Path: got %q, want %q", got.Path, event.Path)
	}
	if got.Action != event.Action {
		t.Errorf("Action: got %q, want %q", got.Action, event.Action)
	}
	if len(got.ProcessTree) != 2 {
		t.Fatalf("ProcessTree len: got %d, want 2", len(got.ProcessTree))
	}
	if got.ProcessTree[0].Name != "cat" {
		t.Errorf("ProcessTree[0].Name: got %q, want %q", got.ProcessTree[0].Name, "cat")
	}
}

func TestDecisionResponse_JSONRoundtrip(t *testing.T) {
	resp := DecisionResponse{
		ID:             "abc123",
		Allow:          true,
		AutoAllowAll:   false,
		WhitelistChain: true,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got DecisionResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ID != resp.ID {
		t.Errorf("ID: got %q, want %q", got.ID, resp.ID)
	}
	if got.Allow != resp.Allow {
		t.Errorf("Allow: got %v, want %v", got.Allow, resp.Allow)
	}
	if got.WhitelistChain != resp.WhitelistChain {
		t.Errorf("WhitelistChain: got %v, want %v", got.WhitelistChain, resp.WhitelistChain)
	}
}

func TestDecisionResponse_OmitEmptyFields(t *testing.T) {
	resp := DecisionResponse{ID: "x", Allow: true}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// AutoAllowAll and WhitelistChain are false — should be omitted
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	if _, ok := raw["auto_allow_all"]; ok {
		t.Error("auto_allow_all should be omitted when false")
	}
	if _, ok := raw["whitelist_chain"]; ok {
		t.Error("whitelist_chain should be omitted when false")
	}
}

func TestEnvelope_PromptType(t *testing.T) {
	event := PromptEvent{ID: "x", Path: "/foo"}
	env := Envelope{Type: "prompt", Prompt: &event}

	data, _ := json.Marshal(env)
	var got Envelope
	json.Unmarshal(data, &got)

	if got.Type != "prompt" {
		t.Errorf("Type: got %q, want %q", got.Type, "prompt")
	}
	if got.Prompt == nil || got.Prompt.Path != "/foo" {
		t.Errorf("Prompt not preserved")
	}
	if got.Decided != nil {
		t.Errorf("Decided should be nil")
	}
}

func TestEnvelope_DecidedType(t *testing.T) {
	env := Envelope{Type: "decided", Decided: &DecidedEvent{ID: "x", Allow: true}}

	data, _ := json.Marshal(env)
	var got Envelope
	json.Unmarshal(data, &got)

	if got.Type != "decided" {
		t.Errorf("Type: got %q, want %q", got.Type, "decided")
	}
	if got.Decided == nil || !got.Decided.Allow {
		t.Errorf("Decided not preserved")
	}
}
