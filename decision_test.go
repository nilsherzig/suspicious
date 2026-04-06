package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestResolveDecision_PromptOnFirstAccess(t *testing.T) {
	cache := make(map[int32]uint32)
	prompted := 0
	prompt := func() uint32 {
		prompted++
		return unix.FAN_ALLOW
	}

	result := resolveDecision(42, cache, prompt)

	if result != unix.FAN_ALLOW {
		t.Errorf("expected FAN_ALLOW, got %d", result)
	}
	if prompted != 1 {
		t.Errorf("expected prompt called once, got %d", prompted)
	}
}

func TestResolveDecision_CachesOnSecondAccess(t *testing.T) {
	cache := make(map[int32]uint32)
	prompted := 0
	prompt := func() uint32 {
		prompted++
		return unix.FAN_ALLOW
	}

	resolveDecision(42, cache, prompt)
	result := resolveDecision(42, cache, prompt)

	if result != unix.FAN_ALLOW {
		t.Errorf("expected FAN_ALLOW, got %d", result)
	}
	if prompted != 1 {
		t.Errorf("expected prompt called only once for same PID, got %d", prompted)
	}
}

func TestResolveDecision_DifferentPIDsPromptSeparately(t *testing.T) {
	cache := make(map[int32]uint32)
	prompted := 0
	prompt := func() uint32 {
		prompted++
		return unix.FAN_ALLOW
	}

	resolveDecision(42, cache, prompt)
	resolveDecision(99, cache, prompt)

	if prompted != 2 {
		t.Errorf("expected prompt called twice for different PIDs, got %d", prompted)
	}
}

func TestResolveDecision_CachesDenyDecision(t *testing.T) {
	cache := make(map[int32]uint32)
	prompted := 0
	prompt := func() uint32 {
		prompted++
		return unix.FAN_DENY
	}

	resolveDecision(42, cache, prompt)
	result := resolveDecision(42, cache, prompt)

	if result != unix.FAN_DENY {
		t.Errorf("expected FAN_DENY, got %d", result)
	}
	if prompted != 1 {
		t.Errorf("expected prompt called only once, got %d", prompted)
	}
}
