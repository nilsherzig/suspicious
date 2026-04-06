//go:build integration

package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests require root / CAP_SYS_ADMIN (fanotify).
// Run with: sudo go test -tags integration -v ./...

func TestFanotifyDetectsFileAccess(t *testing.T) {
	dir := filepath.Join("testfiles", "detect_access")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	targetFile := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(targetFile, []byte("sensitive"), 0644); err != nil {
		t.Fatal(err)
	}

	cfgPath := writeTempConfig(t, []string{dir}, true)
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cmd := exec.Command(suspiciousBinary(t), cfgPath)
	cmd.Env = append(os.Environ(), "SUSPICIOUS_SOCKET="+socketPath)
	out, _ := startAndCapture(t, cmd)

	// Give the daemon time to initialize fanotify and create the socket
	time.Sleep(400 * time.Millisecond)

	// Trigger an access
	f, err := os.Open(targetFile)
	if err != nil {
		t.Fatalf("open target file: %v", err)
	}
	f.Close()

	time.Sleep(200 * time.Millisecond)
	cmd.Process.Signal(os.Interrupt)
	time.Sleep(100 * time.Millisecond)

	output := out.String()
	if !strings.Contains(output, "secret.txt") {
		t.Errorf("expected output to mention secret.txt, got:\n%s", output)
	}
	if !strings.Contains(output, "Zugriff erkannt") {
		t.Errorf("expected 'Zugriff erkannt' in output, got:\n%s", output)
	}
}

func TestFanotifyDetectsDirectoryAccess(t *testing.T) {
	dir := filepath.Join("testfiles", "detect_dir")
	subdir := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	fileInSubdir := filepath.Join(subdir, "data.txt")
	if err := os.WriteFile(fileInSubdir, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	cfgPath := writeTempConfig(t, []string{dir}, true)
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	cmd := exec.Command(suspiciousBinary(t), cfgPath)
	cmd.Env = append(os.Environ(), "SUSPICIOUS_SOCKET="+socketPath)
	out, _ := startAndCapture(t, cmd)

	time.Sleep(400 * time.Millisecond)

	f, openErr := os.Open(fileInSubdir)
	if openErr != nil {
		t.Fatalf("open file in subdir: %v", openErr)
	}
	f.Close()

	time.Sleep(200 * time.Millisecond)
	cmd.Process.Signal(os.Interrupt)
	time.Sleep(100 * time.Millisecond)

	output := out.String()
	if !strings.Contains(output, "data.txt") {
		t.Errorf("expected output to mention data.txt, got:\n%s", output)
	}
}

func TestFanotifyBlocksAccess(t *testing.T) {
	dir := filepath.Join("testfiles", "block_access")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	targetFile := filepath.Join(dir, "blocked.txt")
	if err := os.WriteFile(targetFile, []byte("blocked content"), 0644); err != nil {
		t.Fatal(err)
	}

	cfgPath := writeTempConfig(t, []string{dir}, false)
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	// Use a very short timeout so the daemon auto-denies without needing a CLI
	daemonEnv := append(os.Environ(),
		"SUSPICIOUS_SOCKET="+socketPath,
		"SUSPICIOUS_TIMEOUT=100ms",
	)

	bin := suspiciousBinary(t)
	cmd := exec.Command(bin, cfgPath)
	cmd.Env = daemonEnv
	out, _ := startAndCapture(t, cmd)

	time.Sleep(400 * time.Millisecond)

	// This open should be blocked (FAN_DENY via auto-deny timeout)
	_, openErr := os.Open(targetFile)

	time.Sleep(300 * time.Millisecond)
	cmd.Process.Signal(os.Interrupt)
	time.Sleep(100 * time.Millisecond)

	output := out.String()
	if !strings.Contains(output, "blockiert") {
		t.Errorf("expected 'blockiert' in output, got:\n%s", output)
	}
	if openErr == nil {
		t.Error("expected open to fail due to FAN_DENY, but it succeeded")
	}
}

func TestFanotifyAllowsViaAttachCLI(t *testing.T) {
	dir := filepath.Join("testfiles", "allow_via_cli")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	targetFile := filepath.Join(dir, "guarded.txt")
	if err := os.WriteFile(targetFile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	cfgPath := writeTempConfig(t, []string{dir}, false)
	socketPath := filepath.Join(t.TempDir(), "test.sock")

	bin := suspiciousBinary(t)
	daemonEnv := append(os.Environ(),
		"SUSPICIOUS_SOCKET="+socketPath,
		"SUSPICIOUS_TIMEOUT=5s",
	)

	daemonCmd := exec.Command(bin, cfgPath)
	daemonCmd.Env = daemonEnv
	daemonOut, _ := startAndCapture(t, daemonCmd)

	// Wait for daemon + socket
	time.Sleep(400 * time.Millisecond)

	// Start CLI, pipe "j\n" (allow)
	cliCmd := exec.Command(bin, "attach", socketPath)
	cliCmd.Stdin = strings.NewReader("j\n")
	cliOut, _ := startAndCapture(t, cliCmd)

	time.Sleep(100 * time.Millisecond)

	// Trigger access — CLI should allow it
	f, openErr := os.Open(targetFile)
	if openErr == nil {
		f.Close()
	}

	time.Sleep(300 * time.Millisecond)
	daemonCmd.Process.Signal(os.Interrupt)
	cliCmd.Process.Signal(os.Interrupt)
	time.Sleep(100 * time.Millisecond)

	if openErr != nil {
		t.Errorf("expected open to succeed (CLI allowed), got: %v\nDaemon output:\n%s\nCLI output:\n%s",
			openErr, daemonOut.String(), cliOut.String())
	}
}

// writeTempConfig writes a config.yaml to a temp file and returns its path.
func writeTempConfig(t *testing.T, paths []string, allowAll bool) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("paths:\n")
	for _, p := range paths {
		sb.WriteString("  - " + p + "\n")
	}
	if allowAll {
		sb.WriteString("allow_all: true\n")
	} else {
		sb.WriteString("allow_all: false\n")
	}
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(sb.String())
	f.Close()
	return f.Name()
}

// suspiciousBinary builds the binary and returns its path.
func suspiciousBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "suspicious")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

// startAndCapture starts the command and returns a buffer that captures stdout+stderr.
func startAndCapture(t *testing.T, cmd *exec.Cmd) (*strings.Builder, error) {
	t.Helper()
	var buf strings.Builder
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		t.Fatalf("start command: %v", err)
	}
	go func() {
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			buf.WriteString(scanner.Text() + "\n")
		}
	}()
	t.Cleanup(func() {
		pw.Close()
		pr.Close()
	})
	return &buf, nil
}
