package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsParentChainAllowed_MatchesPrefix(t *testing.T) {
	pc := PathConfig{
		Path:              "/tmp/foo",
		AllowParentChains: []ParentChain{{"git", "lazygit", "zsh"}},
	}
	tree := []ProcessInfo{
		{Name: "git"},
		{Name: "lazygit"},
		{Name: "zsh"},
		{Name: "systemd"},
	}
	if !pc.isParentChainAllowed(tree) {
		t.Error("expected chain to match")
	}
}

func TestIsParentChainAllowed_ExactMatch(t *testing.T) {
	pc := PathConfig{
		Path:              "/tmp/foo",
		AllowParentChains: []ParentChain{{"git", "lazygit"}},
	}
	tree := []ProcessInfo{
		{Name: "git"},
		{Name: "lazygit"},
	}
	if !pc.isParentChainAllowed(tree) {
		t.Error("expected exact chain to match")
	}
}

func TestIsParentChainAllowed_NoMatch(t *testing.T) {
	pc := PathConfig{
		Path:              "/tmp/foo",
		AllowParentChains: []ParentChain{{"git", "lazygit", "zsh"}},
	}
	tree := []ProcessInfo{
		{Name: "curl"},
		{Name: "bash"},
	}
	if pc.isParentChainAllowed(tree) {
		t.Error("expected chain not to match")
	}
}

func TestIsParentChainAllowed_PartialMismatch(t *testing.T) {
	pc := PathConfig{
		Path:              "/tmp/foo",
		AllowParentChains: []ParentChain{{"git", "lazygit", "zsh"}},
	}
	tree := []ProcessInfo{
		{Name: "git"},
		{Name: "bash"}, // wrong parent
		{Name: "zsh"},
	}
	if pc.isParentChainAllowed(tree) {
		t.Error("expected partial mismatch not to match")
	}
}

func TestIsParentChainAllowed_ChainLongerThanTree(t *testing.T) {
	pc := PathConfig{
		Path:              "/tmp/foo",
		AllowParentChains: []ParentChain{{"git", "lazygit", "zsh", "tmux"}},
	}
	tree := []ProcessInfo{
		{Name: "git"},
		{Name: "lazygit"},
	}
	if pc.isParentChainAllowed(tree) {
		t.Error("expected chain longer than tree not to match")
	}
}

func TestIsParentChainAllowed_MultipleChains(t *testing.T) {
	pc := PathConfig{
		Path: "/tmp/foo",
		AllowParentChains: []ParentChain{
			{"ssh", "bash"},
			{"git", "lazygit", "zsh"},
		},
	}
	tree := []ProcessInfo{
		{Name: "git"},
		{Name: "lazygit"},
		{Name: "zsh"},
	}
	if !pc.isParentChainAllowed(tree) {
		t.Error("expected second chain to match")
	}
}

func TestIsParentChainAllowed_EmptyChains(t *testing.T) {
	pc := PathConfig{
		Path:              "/tmp/foo",
		AllowParentChains: nil,
	}
	tree := []ProcessInfo{{Name: "git"}}
	if pc.isParentChainAllowed(tree) {
		t.Error("expected no match when no chains configured")
	}
}

func TestLoadConfig_ParentChains(t *testing.T) {
	dir := t.TempDir()
	content := `
paths:
  - path: /tmp/foo
    allow_parent_chains:
      - git,lazygit,zsh
      - ssh,bash
`
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(cfg.Paths))
	}
	chains := cfg.Paths[0].AllowParentChains
	if len(chains) != 2 {
		t.Fatalf("expected 2 chains, got %d", len(chains))
	}
	if len(chains[0]) != 3 || chains[0][0] != "git" || chains[0][1] != "lazygit" || chains[0][2] != "zsh" {
		t.Errorf("unexpected first chain: %v", chains[0])
	}
	if len(chains[1]) != 2 || chains[1][0] != "ssh" || chains[1][1] != "bash" {
		t.Errorf("unexpected second chain: %v", chains[1])
	}
}

func TestLoadConfig_ParentChains_WithSpaces(t *testing.T) {
	dir := t.TempDir()
	content := `
paths:
  - path: /tmp/foo
    allow_parent_chains:
      - "git, lazygit, zsh"
`
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	chain := cfg.Paths[0].AllowParentChains[0]
	if len(chain) != 3 || chain[0] != "git" || chain[1] != "lazygit" || chain[2] != "zsh" {
		t.Errorf("unexpected chain (spaces not trimmed?): %v", chain)
	}
}

func TestParentChain_MarshalRoundtrip(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	cfg := &Config{
		Paths: []PathConfig{
			{
				Path:              "/tmp/foo",
				AllowParentChains: []ParentChain{{"git", "lazygit", "zsh"}},
			},
		},
	}

	if err := cfg.addParentChain("/tmp/foo/file", ParentChain{"ssh", "bash"}, configPath); err != nil {
		t.Fatalf("addParentChain: %v", err)
	}

	loaded, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig after save: %v", err)
	}
	chains := loaded.Paths[0].AllowParentChains
	if len(chains) != 2 {
		t.Fatalf("expected 2 chains after roundtrip, got %d", len(chains))
	}
	if chains[1][0] != "ssh" || chains[1][1] != "bash" {
		t.Errorf("unexpected second chain after roundtrip: %v", chains[1])
	}
}
