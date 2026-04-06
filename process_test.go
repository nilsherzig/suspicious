package main

import (
	"os"
	"testing"
)

func TestResolveProcessTree_IncludesCurrentProcess(t *testing.T) {
	// The current test process has a known PID and at least one parent.
	pid := int32(os.Getpid())
	tree := resolveProcessTree(pid)

	if len(tree) == 0 {
		t.Fatal("expected at least one entry in process tree")
	}
	// First entry should be the current process itself.
	if tree[0].Pid != pid {
		t.Errorf("expected first entry pid=%d, got %d", pid, tree[0].Pid)
	}
}

func TestResolveProcessTree_HasParent(t *testing.T) {
	pid := int32(os.Getpid())
	tree := resolveProcessTree(pid)

	if len(tree) < 2 {
		t.Fatal("expected at least two entries (process + parent)")
	}
}

func TestResolveProcessTree_StopsAtRoot(t *testing.T) {
	pid := int32(os.Getpid())
	tree := resolveProcessTree(pid)

	// Should terminate eventually (not infinite loop). Last entry should be
	// PID 1 or a process whose parent is 0.
	last := tree[len(tree)-1]
	if last.Pid <= 0 {
		t.Errorf("unexpected last pid: %d", last.Pid)
	}
}

func TestResolveProcessTree_UnknownPID(t *testing.T) {
	// A very high PID that almost certainly doesn't exist.
	tree := resolveProcessTree(999999999)
	// Should return empty or a single unknown entry, not panic.
	_ = tree
}
