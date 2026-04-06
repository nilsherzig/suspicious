package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestResolveDecision_PromptOnFirstAccess(t *testing.T) {
	cache := make(map[pidFileKey]uint32)
	prompted := 0
	prompt := func() uint32 {
		prompted++
		return unix.FAN_ALLOW
	}

	result := resolveDecision(42, "/etc/passwd", cache, prompt)

	if result != unix.FAN_ALLOW {
		t.Errorf("expected FAN_ALLOW, got %d", result)
	}
	if prompted != 1 {
		t.Errorf("expected prompt called once, got %d", prompted)
	}
}

func TestResolveDecision_CachesOnSecondAccessSameFile(t *testing.T) {
	cache := make(map[pidFileKey]uint32)
	prompted := 0
	prompt := func() uint32 {
		prompted++
		return unix.FAN_ALLOW
	}

	resolveDecision(42, "/etc/passwd", cache, prompt)
	result := resolveDecision(42, "/etc/passwd", cache, prompt)

	if result != unix.FAN_ALLOW {
		t.Errorf("expected FAN_ALLOW, got %d", result)
	}
	if prompted != 1 {
		t.Errorf("expected prompt called only once for same PID+file, got %d", prompted)
	}
}

func TestResolveDecision_DifferentFilesSamePIDPromptSeparately(t *testing.T) {
	cache := make(map[pidFileKey]uint32)
	prompted := 0
	prompt := func() uint32 {
		prompted++
		return unix.FAN_ALLOW
	}

	resolveDecision(42, "/etc/passwd", cache, prompt)
	resolveDecision(42, "/etc/hosts", cache, prompt)

	if prompted != 2 {
		t.Errorf("expected prompt called twice for different files with same PID, got %d", prompted)
	}
}

func TestResolveDecision_DifferentPIDsSameFilePromptSeparately(t *testing.T) {
	cache := make(map[pidFileKey]uint32)
	prompted := 0
	prompt := func() uint32 {
		prompted++
		return unix.FAN_ALLOW
	}

	resolveDecision(42, "/etc/passwd", cache, prompt)
	resolveDecision(99, "/etc/passwd", cache, prompt)

	if prompted != 2 {
		t.Errorf("expected prompt called twice for different PIDs, got %d", prompted)
	}
}

func TestResolveDecision_CachesDenyDecision(t *testing.T) {
	cache := make(map[pidFileKey]uint32)
	prompted := 0
	prompt := func() uint32 {
		prompted++
		return unix.FAN_DENY
	}

	resolveDecision(42, "/etc/passwd", cache, prompt)
	result := resolveDecision(42, "/etc/passwd", cache, prompt)

	if result != unix.FAN_DENY {
		t.Errorf("expected FAN_DENY, got %d", result)
	}
	if prompted != 1 {
		t.Errorf("expected prompt called only once, got %d", prompted)
	}
}
