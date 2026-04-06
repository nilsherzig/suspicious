package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ANSI colors
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

const defaultSocketPath = "/run/suspicious/events.sock"
const defaultTimeout = 5 * time.Second

func main() {
	// Subcommand dispatch
	if len(os.Args) > 1 && os.Args[1] == "attach" {
		socketPath := defaultSocketPath
		if v := os.Getenv("SUSPICIOUS_SOCKET"); v != "" {
			socketPath = v
		}
		if len(os.Args) > 2 {
			socketPath = os.Args[2]
		}
		runAttach(socketPath)
		return
	}

	runDaemon()
}

func runDaemon() {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config (%s): %v\n", configPath, err)
		os.Exit(1)
	}

	socketPath := defaultSocketPath
	if v := os.Getenv("SUSPICIOUS_SOCKET"); v != "" {
		socketPath = v
	}
	timeout := defaultTimeout
	if v := os.Getenv("SUSPICIOUS_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		}
	}

	server := NewSocketServer(timeout)
	if err := server.Start(socketPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start socket (%s): %v\n", socketPath, err)
		os.Exit(1)
	}
	defer server.Stop()

	// FAN_CLASS_CONTENT is required for permission events
	// FAN_UNLIMITED_QUEUE prevents event drops under load
	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_UNLIMITED_QUEUE,
		unix.O_RDONLY|unix.O_CLOEXEC,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fanotify_init failed: %v\nRequires root / CAP_SYS_ADMIN.\n", err)
		os.Exit(1)
	}
	defer unix.Close(fd)

	marked := 0
	for _, pc := range cfg.Paths {
		info, err := os.Stat(pc.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sWarning:%s %s not found, skipping: %v\n", colorYellow, colorReset, pc.Path, err)
			continue
		}

		mask := uint64(unix.FAN_OPEN_PERM | unix.FAN_ACCESS_PERM)
		if info.IsDir() {
			mask |= unix.FAN_EVENT_ON_CHILD
		}

		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, pc.Path); err != nil {
			fmt.Fprintf(os.Stderr, "fanotify_mark failed for %s: %v\n", pc.Path, err)
			os.Exit(1)
		}

		fmt.Printf("%s%s[fanotify-guard]%s Watching: %s%s%s\n", colorBold, colorCyan, colorReset, colorYellow, pc.Path, colorReset)
		marked++
	}

	if marked == 0 {
		fmt.Fprintf(os.Stderr, "Error: no paths could be watched.\n")
		os.Exit(1)
	}

	fmt.Printf("%s%s[fanotify-guard]%s Socket: %s\n", colorBold, colorCyan, colorReset, socketPath)
	fmt.Printf("%s%s[fanotify-guard]%s Timeout: %s (auto-deny if no response)\n", colorBold, colorCyan, colorReset, timeout)

	pidCache := make(map[pidFileKey]uint32)
	autoAllow := cfg.AllowAll
	if autoAllow {
		fmt.Printf("%s(Log mode: all access automatically allowed)%s\n", colorCyan, colorReset)
	}
	fmt.Println()

	// Cleanup on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n%s[fanotify-guard]%s Shutting down...\n", colorCyan, colorReset)
		unix.Close(fd)
		os.Exit(0)
	}()

	eventSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	buf := make([]byte, 4096)

	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			fmt.Fprintf(os.Stderr, "read error: %v\n", err)
			break
		}

		offset := 0
		for offset+eventSize <= n {
			event := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))

			if event.Fd < 0 {
				offset += int(event.Event_len)
				continue
			}

			filePath := resolveFilePath(event.Fd)
			tree := resolveProcessTree(event.Pid)
			eventType := describeEvent(event.Mask)

			// Log the event
			fmt.Printf("%s%s─── Access detected ──── %s%s%s\n", colorBold, colorCyan, colorReset, time.Now().Format("2006-01-02 15:04:05"), colorReset)
			fmt.Printf("  File:    %s%s%s\n", colorYellow, filePath, colorReset)
			if len(tree) > 0 {
				fmt.Printf("  Process: %s%s%s (PID %d)\n", colorBold, tree[0].Name, colorReset, tree[0].Pid)
				fmt.Printf("  Cmd:     %s\n", tree[0].Cmd)
				if len(tree) > 1 {
					parts := make([]string, len(tree)-1)
					for i, p := range tree[1:] {
						parts[i] = p.Name
					}
					fmt.Printf("  Parents: %s\n", strings.Join(parts, " ← "))
				}
			}
			fmt.Printf("  Action:  %s\n", eventType)

			var response uint32
			pathCfg := cfg.findPathConfig(filePath)
			if autoAllow {
				response = unix.FAN_ALLOW
				fmt.Printf("  → %sauto-allowed%s\n\n", colorGreen, colorReset)
			} else if pathCfg != nil && pathCfg.isBinaryAllowed(resolveProcessExe(event.Pid)) {
				response = unix.FAN_ALLOW
				fmt.Printf("  → %sallowed (whitelisted binary)%s\n\n", colorGreen, colorReset)
			} else if pathCfg != nil && pathCfg.isParentChainAllowed(tree) {
				response = unix.FAN_ALLOW
				fmt.Printf("  → %sallowed (whitelisted parent chain)%s\n\n", colorGreen, colorReset)
			} else {
				_, alreadyCached := pidCache[pidFileKey{pid: event.Pid, path: filePath}]
				promptEvent := PromptEvent{
					ID:          generatePromptID(),
					Pid:         event.Pid,
					Path:        filePath,
					ProcessTree: tree,
					Action:      eventType,
					Timestamp:   time.Now(),
				}
				response = resolveDecision(event.Pid, filePath, pidCache, func() uint32 {
					decision := server.BroadcastPrompt(promptEvent)

					if decision.AutoAllowAll {
						autoAllow = true
						fmt.Printf("  → %sallowed (auto-allowing all from now on)%s\n\n", colorYellow, colorReset)
						return unix.FAN_ALLOW
					}
					if decision.WhitelistChain {
						chain := make(ParentChain, len(tree))
						for i, p := range tree {
							chain[i] = p.Name
						}
						addChainToWhitelist(cfg, configPath, filePath, chain)
						fmt.Printf("  → %sallowed (chain added to whitelist)%s\n\n", colorYellow, colorReset)
						return unix.FAN_ALLOW
					}
					if decision.Allow {
						fmt.Printf("  → %sallowed%s\n\n", colorGreen, colorReset)
						return unix.FAN_ALLOW
					}
					fmt.Printf("  → %sdenied%s\n\n", colorRed, colorReset)
					return unix.FAN_DENY
				})
				if alreadyCached {
					if response == unix.FAN_ALLOW {
						fmt.Printf("  → %sallowed (PID %d + file already confirmed)%s\n\n", colorGreen, event.Pid, colorReset)
					} else {
						fmt.Printf("  → %sdenied (PID %d + file already rejected)%s\n\n", colorRed, event.Pid, colorReset)
					}
				}
			}

			resp := unix.FanotifyResponse{
				Fd:       event.Fd,
				Response: response,
			}
			respBytes := (*[unsafe.Sizeof(resp)]byte)(unsafe.Pointer(&resp))
			if err := writeFanotifyResponse(fd, respBytes[:]); err != nil {
				fmt.Fprintf(os.Stderr, "response write error: %v\n", err)
			}

			unix.Close(int(event.Fd))
			offset += int(event.Event_len)
		}
	}
}

type pidFileKey struct {
	pid  int32
	path string
}

// resolveDecision returns a cached allow/deny for the (pid, path) pair if already decided,
// otherwise calls prompt() to get the user's decision and stores it.
func resolveDecision(pid int32, path string, cache map[pidFileKey]uint32, prompt func() uint32) uint32 {
	key := pidFileKey{pid: pid, path: path}
	if response, ok := cache[key]; ok {
		return response
	}
	response := prompt()
	cache[key] = response
	return response
}

func writeFanotifyResponse(fd int, data []byte) error {
	_, err := unix.Write(fd, data)
	return err
}

func resolveProcessExe(pid int32) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return path
}

func resolveFilePath(fd int32) string {
	link := fmt.Sprintf("/proc/self/fd/%d", fd)
	path, err := os.Readlink(link)
	if err != nil {
		return fmt.Sprintf("(fd=%d, path unresolvable)", fd)
	}
	return path
}

// addChainToWhitelist appends chain to the allow_parent_chains of the PathConfig
// matching filePath, then persists the updated config to disk.
func addChainToWhitelist(cfg *Config, configPath string, filePath string, chain ParentChain) {
	if err := cfg.addParentChain(filePath, chain, configPath); err != nil {
		fmt.Fprintf(os.Stderr, "  %v\n", err)
		return
	}
	fmt.Printf("  %sChain saved to %s%s\n", colorCyan, configPath, colorReset)
}

func describeEvent(mask uint64) string {
	var parts []string
	if mask&unix.FAN_OPEN_PERM != 0 {
		parts = append(parts, "OPEN")
	}
	if mask&unix.FAN_ACCESS_PERM != 0 {
		parts = append(parts, "READ")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", mask)
	}
	return strings.Join(parts, " | ")
}
