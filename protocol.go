package main

import "time"

// Envelope wraps all messages sent from daemon to CLI over the Unix socket.
type Envelope struct {
	Type    string        `json:"type"`              // "prompt" | "decided"
	Prompt  *PromptEvent  `json:"prompt,omitempty"`
	Decided *DecidedEvent `json:"decided,omitempty"`
}

// PromptEvent is sent from daemon to CLI when a file access needs a human decision.
type PromptEvent struct {
	ID          string        `json:"id"`
	Pid         int32         `json:"pid"`
	Path        string        `json:"path"`
	ProcessTree []ProcessInfo `json:"process_tree"`
	Action      string        `json:"action"`
	Timestamp   time.Time     `json:"timestamp"`
}

// DecisionResponse is sent from CLI to daemon.
type DecisionResponse struct {
	ID             string `json:"id"`
	Allow          bool   `json:"allow"`
	AutoAllowAll   bool   `json:"auto_allow_all,omitempty"`
	WhitelistChain bool   `json:"whitelist_chain,omitempty"`
}

// DecidedEvent is broadcast to all clients once any client has answered a prompt.
type DecidedEvent struct {
	ID    string `json:"id"`
	Allow bool   `json:"allow"`
}
