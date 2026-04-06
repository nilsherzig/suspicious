package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_ValidFile(t *testing.T) {
	dir := t.TempDir()
	content := `
paths:
  - /tmp/foo
  - /tmp/bar
allow_all: true
`
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(cfg.Paths))
	}
	if cfg.Paths[0] != "/tmp/foo" || cfg.Paths[1] != "/tmp/bar" {
		t.Errorf("unexpected paths: %v", cfg.Paths)
	}
	if !cfg.AllowAll {
		t.Error("expected allow_all to be true")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := loadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadConfig_ExpandsEnvVars(t *testing.T) {
	dir := t.TempDir()
	content := `
paths:
  - $HOME/.ssh
  - ${HOME}/.config
`
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	home := os.Getenv("HOME")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Paths[0] != home+"/.ssh" {
		t.Errorf("expected %s/.ssh, got %s", home, cfg.Paths[0])
	}
	if cfg.Paths[1] != home+"/.config" {
		t.Errorf("expected %s/.config, got %s", home, cfg.Paths[1])
	}
}

func TestLoadConfig_EmptyPaths(t *testing.T) {
	dir := t.TempDir()
	content := `paths: []`
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := loadConfig(path)
	if err == nil {
		t.Error("expected error for empty paths")
	}
}
