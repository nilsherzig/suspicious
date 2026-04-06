package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// runAttach connects to the daemon socket and presents prompts interactively.
func runAttach(socketPath string) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to daemon (%s): %v\n", socketPath, err)
		fmt.Fprintf(os.Stderr, "Is the daemon running? Start it with: sudo suspicious [config.yaml]\n")
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("%s%s[suspicious-cli]%s Connected to %s\n\n", colorBold, colorCyan, colorReset, socketPath)

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	reader := bufio.NewReader(os.Stdin)

	// Track which prompts are still open so "decided" notifications can skip them.
	type pendingEntry struct {
		event   PromptEvent
		decided bool
	}
	pending := make(map[string]*pendingEntry)
	// Queue of prompt IDs in arrival order
	var queue []string
	// Channel to signal new work
	incoming := make(chan Envelope, 32)

	// Background reader: push all incoming envelopes onto the channel
	go func() {
		for {
			var env Envelope
			if err := dec.Decode(&env); err != nil {
				close(incoming)
				return
			}
			incoming <- env
		}
	}()

	for {
		// Drain any queued envelopes before blocking on stdin
	drainLoop:
		for {
			select {
			case env, ok := <-incoming:
				if !ok {
					fmt.Printf("\n%s[suspicious-cli]%s Daemon connection closed.\n", colorCyan, colorReset)
					return
				}
				switch env.Type {
				case "prompt":
					pending[env.Prompt.ID] = &pendingEntry{event: *env.Prompt}
					queue = append(queue, env.Prompt.ID)
				case "decided":
					if p, ok := pending[env.Decided.ID]; ok {
						p.decided = true
					}
				}
			default:
				break drainLoop
			}
		}

		// Find the next undecided prompt in the queue
		for len(queue) > 0 && (pending[queue[0]] == nil || pending[queue[0]].decided) {
			delete(pending, queue[0])
			queue = queue[1:]
		}

		if len(queue) == 0 {
			// Block waiting for the next envelope
			env, ok := <-incoming
			if !ok {
				fmt.Printf("\n%s[suspicious-cli]%s Daemon connection closed.\n", colorCyan, colorReset)
				return
			}
			switch env.Type {
			case "prompt":
				pending[env.Prompt.ID] = &pendingEntry{event: *env.Prompt}
				queue = append(queue, env.Prompt.ID)
			case "decided":
				if p, ok := pending[env.Decided.ID]; ok {
					p.decided = true
				}
			}
			continue
		}

		// Display and handle the next prompt
		id := queue[0]
		queue = queue[1:]
		pe := pending[id]

		if pe.decided {
			delete(pending, id)
			continue
		}

		// Check if already decided while we were looking
		fmt.Print(formatPromptEvent(pe.event))
		fmt.Printf("  Allow? [%sY%s/n/%sw%s=chain whitelist]: ", colorGreen, colorReset, colorYellow, colorReset)

		// Non-blocking check: did daemon decide this while we were printing?
		select {
		case env := <-incoming:
			// Re-queue and handle this envelope first
			switch env.Type {
			case "prompt":
				pending[env.Prompt.ID] = &pendingEntry{event: *env.Prompt}
				queue = append(queue, env.Prompt.ID)
			case "decided":
				if env.Decided.ID == id {
					// This prompt was decided by another client
					delete(pending, id)
					fmt.Printf("\n  → %salready decided by another client%s\n\n", colorYellow, colorReset)
					continue
				}
				if p, ok := pending[env.Decided.ID]; ok {
					p.decided = true
				}
			}
		default:
		}

		input, _ := reader.ReadString('\n')
		resp := parseDecisionInput(strings.TrimSpace(input), pe.event)
		delete(pending, id)

		if err := enc.Encode(resp); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to send decision: %v\n", err)
			return
		}

		switch {
		case resp.WhitelistChain:
			fmt.Printf("  → %sAllowed + parent chain added to whitelist%s\n\n", colorGreen, colorReset)
		case resp.Allow:
			fmt.Printf("  → %sAllowed%s\n\n", colorGreen, colorReset)
		default:
			fmt.Printf("  → %sDenied%s\n\n", colorRed, colorReset)
		}
	}
}

// parseDecisionInput maps a raw user input string to a DecisionResponse.
func parseDecisionInput(input string, event PromptEvent) DecisionResponse {
	normalized := strings.ToLower(strings.TrimSpace(input))
	resp := DecisionResponse{ID: event.ID}
	switch normalized {
	case "n", "no":
		resp.Allow = false
	case "w":
		resp.Allow = true
		resp.WhitelistChain = true
	default: // y, yes, ""
		resp.Allow = true
	}
	return resp
}

// formatPromptEvent renders a prompt event as an ANSI-colored string for display.
func formatPromptEvent(event PromptEvent) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s%s─── Access detected ──── %s%s%s\n",
		colorBold, colorCyan, colorReset, event.Timestamp.Format("2006-01-02 15:04:05"), colorReset))
	sb.WriteString(fmt.Sprintf("  File:    %s%s%s\n", colorYellow, event.Path, colorReset))
	if len(event.ProcessTree) > 0 {
		p0 := event.ProcessTree[0]
		sb.WriteString(fmt.Sprintf("  Process: %s%s%s (PID %d)\n", colorBold, p0.Name, colorReset, p0.Pid))
		sb.WriteString(fmt.Sprintf("  Cmd:     %s\n", p0.Cmd))
		if len(event.ProcessTree) > 1 {
			parts := make([]string, len(event.ProcessTree)-1)
			for i, p := range event.ProcessTree[1:] {
				parts[i] = p.Name
			}
			sb.WriteString(fmt.Sprintf("  Parents: %s\n", strings.Join(parts, " ← ")))
		}
	}
	sb.WriteString(fmt.Sprintf("  Action:  %s\n", event.Action))
	return sb.String()
}
