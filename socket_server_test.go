package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func tempSocketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.sock")
}

func TestSocketServer_BroadcastPrompt_NoClients_AutoDeny(t *testing.T) {
	srv := NewSocketServer(100 * time.Millisecond)
	path := tempSocketPath(t)
	if err := srv.Start(path); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	event := PromptEvent{ID: "id1", Path: "/etc/passwd", Action: "OPEN"}
	resp := srv.BroadcastPrompt(event)

	if resp.Allow {
		t.Error("expected deny when no client connected, got allow")
	}
	if resp.ID != "id1" {
		t.Errorf("ID: got %q, want %q", resp.ID, "id1")
	}
}

func TestSocketServer_BroadcastPrompt_ClientAllows(t *testing.T) {
	srv := NewSocketServer(2 * time.Second)
	path := tempSocketPath(t)
	if err := srv.Start(path); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	// Connect a mock client
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	// Small delay to let the server register the client
	time.Sleep(20 * time.Millisecond)

	event := PromptEvent{ID: "id2", Path: "/etc/hosts", Action: "OPEN"}
	var result DecisionResponse
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		result = srv.BroadcastPrompt(event)
	}()

	// Client reads the prompt
	var env Envelope
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("client decode: %v", err)
	}
	if env.Type != "prompt" {
		t.Fatalf("expected type=prompt, got %q", env.Type)
	}
	if env.Prompt.ID != "id2" {
		t.Errorf("prompt ID: got %q, want %q", env.Prompt.ID, "id2")
	}

	// Client sends allow
	enc.Encode(DecisionResponse{ID: "id2", Allow: true})

	wg.Wait()

	if !result.Allow {
		t.Error("expected allow, got deny")
	}
}

func TestSocketServer_BroadcastPrompt_ClientDenies(t *testing.T) {
	srv := NewSocketServer(2 * time.Second)
	path := tempSocketPath(t)
	srv.Start(path)
	defer srv.Stop()

	conn, _ := net.Dial("unix", path)
	defer conn.Close()
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	time.Sleep(20 * time.Millisecond)

	event := PromptEvent{ID: "id3", Path: "/etc/shadow", Action: "READ"}
	var result DecisionResponse
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		result = srv.BroadcastPrompt(event)
	}()

	var env Envelope
	dec.Decode(&env)
	enc.Encode(DecisionResponse{ID: "id3", Allow: false})
	wg.Wait()

	if result.Allow {
		t.Error("expected deny, got allow")
	}
}

func TestSocketServer_MultipleClients_FirstResponderWins(t *testing.T) {
	srv := NewSocketServer(2 * time.Second)
	path := tempSocketPath(t)
	srv.Start(path)
	defer srv.Stop()

	conn1, _ := net.Dial("unix", path)
	conn2, _ := net.Dial("unix", path)
	defer conn1.Close()
	defer conn2.Close()

	dec1 := json.NewDecoder(conn1)
	dec2 := json.NewDecoder(conn2)
	enc2 := json.NewEncoder(conn2)
	time.Sleep(30 * time.Millisecond)

	event := PromptEvent{ID: "id4", Path: "/tmp/test", Action: "OPEN"}
	var result DecisionResponse
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		result = srv.BroadcastPrompt(event)
	}()

	// Both clients receive the prompt
	var env1, env2 Envelope
	dec1.Decode(&env1)
	dec2.Decode(&env2)

	if env1.Type != "prompt" || env2.Type != "prompt" {
		t.Fatalf("both clients should receive prompt, got %q and %q", env1.Type, env2.Type)
	}

	// Client 2 responds first (deny)
	enc2.Encode(DecisionResponse{ID: "id4", Allow: false})
	wg.Wait()

	if result.Allow {
		t.Error("client 2 responded deny first, expected deny")
	}
}

func TestSocketServer_NewClientReceivesPendingPrompts(t *testing.T) {
	srv := NewSocketServer(2 * time.Second)
	path := tempSocketPath(t)
	srv.Start(path)
	defer srv.Stop()

	event := PromptEvent{ID: "id5", Path: "/etc/passwd", Action: "OPEN"}
	var result DecisionResponse
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		result = srv.BroadcastPrompt(event)
	}()

	// Slight delay before client connects — prompt is already in-flight
	time.Sleep(30 * time.Millisecond)

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	// Client should still receive the pending prompt
	conn.SetDeadline(time.Now().Add(time.Second))
	var env Envelope
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("client did not receive pending prompt: %v", err)
	}
	if env.Type != "prompt" || env.Prompt.ID != "id5" {
		t.Fatalf("unexpected envelope: %+v", env)
	}

	enc.Encode(DecisionResponse{ID: "id5", Allow: true})
	wg.Wait()

	if !result.Allow {
		t.Error("expected allow from late-connecting client")
	}
}

func TestSocketServer_ClientDisconnect_DoesNotPanic(t *testing.T) {
	srv := NewSocketServer(200 * time.Millisecond)
	path := tempSocketPath(t)
	srv.Start(path)
	defer srv.Stop()

	conn, _ := net.Dial("unix", path)
	time.Sleep(20 * time.Millisecond)
	conn.Close() // disconnect immediately

	// BroadcastPrompt should timeout cleanly, not panic
	event := PromptEvent{ID: "id6", Path: "/tmp/x", Action: "OPEN"}
	resp := srv.BroadcastPrompt(event)
	if resp.Allow {
		t.Error("expected deny after client disconnect + timeout")
	}
}

func TestSocketServer_BroadcastPrompt_NoTimeoutWhenClientAttached(t *testing.T) {
	timeout := 50 * time.Millisecond
	srv := NewSocketServer(timeout)
	path := tempSocketPath(t)
	srv.Start(path)
	defer srv.Stop()

	conn, _ := net.Dial("unix", path)
	defer conn.Close()
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	time.Sleep(20 * time.Millisecond)

	event := PromptEvent{ID: "no-timeout", Path: "/tmp/test", Action: "OPEN"}
	var result DecisionResponse
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		result = srv.BroadcastPrompt(event)
	}()

	var env Envelope
	dec.Decode(&env)

	// Respond well after the timeout duration — should NOT auto-deny
	time.Sleep(timeout * 4)
	enc.Encode(DecisionResponse{ID: "no-timeout", Allow: true})
	wg.Wait()

	if !result.Allow {
		t.Error("expected allow: client was attached and answered; timeout should not fire while a client is connected")
	}
}

func TestSocketServer_LastClientDisconnect_StartsTimeout(t *testing.T) {
	timeout := 80 * time.Millisecond
	srv := NewSocketServer(timeout)
	path := tempSocketPath(t)
	srv.Start(path)
	defer srv.Stop()

	conn, _ := net.Dial("unix", path)
	dec := json.NewDecoder(conn)
	time.Sleep(20 * time.Millisecond)

	event := PromptEvent{ID: "disconnect-timeout", Path: "/tmp/x", Action: "OPEN"}
	var result DecisionResponse
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		result = srv.BroadcastPrompt(event)
	}()

	var env Envelope
	dec.Decode(&env)

	// Disconnect without answering — timeout should now kick in
	conn.Close()

	wg.Wait()

	if result.Allow {
		t.Error("expected deny: last client disconnected without answering")
	}
}

func TestSocketServer_SocketFileCreated(t *testing.T) {
	srv := NewSocketServer(time.Second)
	path := tempSocketPath(t)
	if err := srv.Start(path); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	if _, err := os.Stat(path); err != nil {
		t.Errorf("socket file not created: %v", err)
	}
}

func TestSocketServer_Stop_ClosesListener(t *testing.T) {
	srv := NewSocketServer(time.Second)
	path := tempSocketPath(t)
	srv.Start(path)
	srv.Stop()

	// After Stop, dialing should fail
	_, err := net.Dial("unix", path)
	if err == nil {
		t.Error("expected dial to fail after Stop")
	}
}
