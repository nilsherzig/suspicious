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
	if cfg.Paths[0].Path != "/tmp/foo" || cfg.Paths[1].Path != "/tmp/bar" {
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
	if cfg.Paths[0].Path != home+"/.ssh" {
		t.Errorf("expected %s/.ssh, got %s", home, cfg.Paths[0].Path)
	}
	if cfg.Paths[1].Path != home+"/.config" {
		t.Errorf("expected %s/.config, got %s", home, cfg.Paths[1].Path)
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

func TestLoadConfig_ObjectPath(t *testing.T) {
	dir := t.TempDir()
	content := `
paths:
  - path: /tmp/foo
    allow_binaries:
      - /usr/bin/cat
      - /usr/bin/less
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
	if cfg.Paths[0].Path != "/tmp/foo" {
		t.Errorf("unexpected path: %s", cfg.Paths[0].Path)
	}
	if len(cfg.Paths[0].AllowBinaries) != 2 {
		t.Fatalf("expected 2 allow_binaries, got %d", len(cfg.Paths[0].AllowBinaries))
	}
	if cfg.Paths[0].AllowBinaries[0] != "/usr/bin/cat" {
		t.Errorf("unexpected binary: %s", cfg.Paths[0].AllowBinaries[0])
	}
}

func TestLoadConfig_MixedPaths(t *testing.T) {
	dir := t.TempDir()
	content := `
paths:
  - /tmp/plain
  - path: /tmp/guarded
    allow_binaries:
      - /usr/bin/nvim
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
	if cfg.Paths[0].Path != "/tmp/plain" {
		t.Errorf("unexpected path: %s", cfg.Paths[0].Path)
	}
	if len(cfg.Paths[0].AllowBinaries) != 0 {
		t.Errorf("expected no allow_binaries for plain path")
	}
	if cfg.Paths[1].Path != "/tmp/guarded" {
		t.Errorf("unexpected path: %s", cfg.Paths[1].Path)
	}
	if cfg.Paths[1].AllowBinaries[0] != "/usr/bin/nvim" {
		t.Errorf("unexpected binary: %s", cfg.Paths[1].AllowBinaries[0])
	}
}

func TestLoadConfig_ExpandsEnvVarsInBinaries(t *testing.T) {
	dir := t.TempDir()
	content := `
paths:
  - path: $HOME/.config
    allow_binaries:
      - $HOME/.local/bin/nvim
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
	if cfg.Paths[0].Path != home+"/.config" {
		t.Errorf("expected %s/.config, got %s", home, cfg.Paths[0].Path)
	}
	if cfg.Paths[0].AllowBinaries[0] != home+"/.local/bin/nvim" {
		t.Errorf("expected %s/.local/bin/nvim, got %s", home, cfg.Paths[0].AllowBinaries[0])
	}
}

func TestFindPathConfig(t *testing.T) {
	cfg := &Config{
		Paths: []PathConfig{
			{Path: "/tmp/watched", AllowBinaries: []string{"/usr/bin/cat"}},
			{Path: "/etc/secrets"},
		},
	}

	tests := []struct {
		filePath string
		wantPath string
		wantNil  bool
	}{
		{"/tmp/watched/file.txt", "/tmp/watched", false},
		{"/tmp/watched", "/tmp/watched", false},
		{"/tmp/other/file.txt", "", true},
		{"/etc/secrets/key", "/etc/secrets", false},
	}

	for _, tc := range tests {
		pc := cfg.findPathConfig(tc.filePath)
		if tc.wantNil {
			if pc != nil {
				t.Errorf("findPathConfig(%q): expected nil, got %q", tc.filePath, pc.Path)
			}
		} else {
			if pc == nil {
				t.Errorf("findPathConfig(%q): expected %q, got nil", tc.filePath, tc.wantPath)
			} else if pc.Path != tc.wantPath {
				t.Errorf("findPathConfig(%q): expected %q, got %q", tc.filePath, tc.wantPath, pc.Path)
			}
		}
	}
}

func TestIsBinaryAllowed(t *testing.T) {
	pc := PathConfig{
		Path:          "/tmp/foo",
		AllowBinaries: []string{"/usr/bin/nvim", "/usr/bin/cat"},
	}

	if !pc.isBinaryAllowed("/usr/bin/nvim") {
		t.Error("expected nvim to be allowed")
	}
	if pc.isBinaryAllowed("/usr/bin/vim") {
		t.Error("expected vim to not be allowed")
	}
	if pc.isBinaryAllowed("") {
		t.Error("expected empty string to not be allowed")
	}
}
