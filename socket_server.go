package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SocketServer listens on a Unix socket, fans prompts out to all connected CLI
// clients, and returns the first DecisionResponse received. If no client
// responds within the configured timeout, it returns a deny decision.
type SocketServer struct {
	timeout  time.Duration
	listener net.Listener

	mu      sync.Mutex
	clients []*socketClient
	pending map[string]*pendingPrompt
}

type socketClient struct {
	conn net.Conn
	enc  *json.Encoder
}

type pendingPrompt struct {
	event   PromptEvent
	decided chan DecisionResponse
}

// NewSocketServer creates a server with the given decision timeout.
func NewSocketServer(timeout time.Duration) *SocketServer {
	return &SocketServer{
		timeout: timeout,
		pending: make(map[string]*pendingPrompt),
	}
}

// Start creates the socket file at path and begins accepting connections.
func (s *SocketServer) Start(path string) error {
	os.Remove(path)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen %s: %w", path, err)
	}
	os.Chmod(path, 0660)
	s.listener = l
	go s.acceptLoop()
	return nil
}

// Stop closes the listener and all client connections.
func (s *SocketServer) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.clients {
		c.conn.Close()
	}
}

// BroadcastPrompt sends event to all connected clients and blocks until one
// responds. If no clients are connected the timeout applies immediately. If
// clients are connected the timeout is deferred until the last client
// disconnects (see removeClient).
func (s *SocketServer) BroadcastPrompt(event PromptEvent) DecisionResponse {
	ch := make(chan DecisionResponse, 1)
	pp := &pendingPrompt{event: event, decided: ch}
	env := Envelope{Type: "prompt", Prompt: &event}

	s.mu.Lock()
	s.pending[event.ID] = pp
	hasClients := len(s.clients) > 0
	for _, c := range s.clients {
		c.enc.Encode(env) // best-effort; ignore per-client errors
	}
	s.mu.Unlock()

	if hasClients {
		// At least one client is attached — wait indefinitely.
		// removeClient starts the timeout when the last client drops.
		return <-ch
	}

	// No clients: auto-deny after timeout.
	select {
	case resp := <-ch:
		return resp
	case <-time.After(s.timeout):
		s.mu.Lock()
		delete(s.pending, event.ID)
		s.mu.Unlock()
		return DecisionResponse{ID: event.ID, Allow: false}
	}
}

func (s *SocketServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // listener closed
		}
		c := &socketClient{conn: conn, enc: json.NewEncoder(conn)}
		s.mu.Lock()
		s.clients = append(s.clients, c)
		// Send any prompts that are already waiting for a decision
		for _, pp := range s.pending {
			c.enc.Encode(Envelope{Type: "prompt", Prompt: &pp.event})
		}
		s.mu.Unlock()
		go s.readLoop(c)
	}
}

func (s *SocketServer) readLoop(c *socketClient) {
	defer s.removeClient(c)
	dec := json.NewDecoder(c.conn)
	for {
		var resp DecisionResponse
		if err := dec.Decode(&resp); err != nil {
			return
		}
		s.mu.Lock()
		pp, ok := s.pending[resp.ID]
		if ok {
			delete(s.pending, resp.ID)
		}
		s.mu.Unlock()
		if ok {
			select {
			case pp.decided <- resp:
			default: // already decided by another client
			}
			// Notify all remaining clients that this prompt is settled
			decided := Envelope{Type: "decided", Decided: &DecidedEvent{ID: resp.ID, Allow: resp.Allow}}
			s.mu.Lock()
			for _, other := range s.clients {
				if other != c {
					other.enc.Encode(decided)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *SocketServer) removeClient(c *socketClient) {
	c.conn.Close()
	s.mu.Lock()
	for i, cl := range s.clients {
		if cl == c {
			s.clients = append(s.clients[:i], s.clients[i+1:]...)
			break
		}
	}
	// When the last client drops, start a timeout for every pending prompt so
	// that BroadcastPrompt (which is blocking on <-ch without a timer) doesn't
	// wait forever.
	var toTimeout []*pendingPrompt
	if len(s.clients) == 0 {
		for _, pp := range s.pending {
			toTimeout = append(toTimeout, pp)
		}
	}
	s.mu.Unlock()

	for _, pp := range toTimeout {
		pp := pp
		go func() {
			time.Sleep(s.timeout)
			select {
			case pp.decided <- DecisionResponse{ID: pp.event.ID, Allow: false}:
				s.mu.Lock()
				delete(s.pending, pp.event.ID)
				s.mu.Unlock()
			default: // already answered (e.g. a new client connected and responded)
			}
		}()
	}
}

func generatePromptID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
