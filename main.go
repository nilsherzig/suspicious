package main

import (
	"bufio"
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

func main() {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fehler beim Laden der Config (%s): %v\n", configPath, err)
		os.Exit(1)
	}

	// FAN_CLASS_CONTENT is required for permission events
	// FAN_UNLIMITED_QUEUE prevents event drops under load
	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_UNLIMITED_QUEUE,
		unix.O_RDONLY|unix.O_CLOEXEC,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fanotify_init fehlgeschlagen: %v\nBraucht root / CAP_SYS_ADMIN.\n", err)
		os.Exit(1)
	}
	defer unix.Close(fd)

	marked := 0
	for _, watchPath := range cfg.Paths {
		info, err := os.Stat(watchPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sWarnung:%s %s nicht gefunden, wird übersprungen: %v\n", colorYellow, colorReset, watchPath, err)
			continue
		}

		mask := uint64(unix.FAN_OPEN_PERM | unix.FAN_ACCESS_PERM)
		if info.IsDir() {
			mask |= unix.FAN_EVENT_ON_CHILD
		}

		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, watchPath); err != nil {
			fmt.Fprintf(os.Stderr, "fanotify_mark fehlgeschlagen für %s: %v\n", watchPath, err)
			os.Exit(1)
		}

		fmt.Printf("%s%s[fanotify-guard]%s Überwache: %s%s%s\n", colorBold, colorCyan, colorReset, colorYellow, watchPath, colorReset)
		marked++
	}

	if marked == 0 {
		fmt.Fprintf(os.Stderr, "Fehler: Kein einziger Pfad konnte überwacht werden.\n")
		os.Exit(1)
	}

	pidCache := make(map[int32]uint32)
	autoAllow := cfg.AllowAll
	if autoAllow {
		fmt.Printf("%s(Log-Modus: alles wird automatisch erlaubt)%s\n", colorCyan, colorReset)
	} else {
		fmt.Printf("Beantworte Zugriffe mit: %s[j]a%s / %s[n]ein%s / %s[a]lle erlauben%s\n",
			colorGreen, colorReset, colorRed, colorReset, colorYellow, colorReset)
	}
	fmt.Println()

	// Cleanup on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n%s[fanotify-guard]%s Beende...\n", colorCyan, colorReset)
		unix.Close(fd)
		os.Exit(0)
	}()

	reader := bufio.NewReader(os.Stdin)
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

			// Resolve the file path from the fd
			filePath := resolveFilePath(event.Fd)

			// Resolve process tree from PID
			tree := resolveProcessTree(event.Pid)

			// Determine event type
			eventType := describeEvent(event.Mask)

			// Print the event info
			fmt.Printf("%s%s─── Zugriff erkannt ──── %s%s%s\n", colorBold, colorCyan, colorReset, time.Now().Format("2006-01-02 15:04:05"), colorReset)
			fmt.Printf("  Datei:   %s%s%s\n", colorYellow, filePath, colorReset)
			if len(tree) > 0 {
				fmt.Printf("  Prozess: %s%s%s (PID %d)\n", colorBold, tree[0].Name, colorReset, tree[0].Pid)
				fmt.Printf("  Cmd:     %s\n", tree[0].Cmd)
				if len(tree) > 1 {
					parts := make([]string, len(tree))
					for i, p := range tree {
						parts[i] = p.Name
					}
					fmt.Printf("  Eltern:  %s\n", strings.Join(parts[1:], " ← "))
				}
			}
			fmt.Printf("  Aktion:  %s\n", eventType)

			var response uint32
			if autoAllow {
				response = unix.FAN_ALLOW
				fmt.Printf("  → %sautomatisch erlaubt%s\n\n", colorGreen, colorReset)
			} else {
				_, alreadyCached := pidCache[event.Pid]
				response = resolveDecision(event.Pid, pidCache, func() uint32 {
					fmt.Printf("  Erlauben? [%sJ%s/n/a]: ", colorGreen, colorReset)
					input, _ := reader.ReadString('\n')
					input = strings.TrimSpace(strings.ToLower(input))

					switch input {
					case "a", "all", "alle":
						autoAllow = true
						fmt.Printf("  → %serlaubt (ab jetzt alles automatisch)%s\n\n", colorYellow, colorReset)
						return unix.FAN_ALLOW
					case "n", "nein", "no":
						fmt.Printf("  → %sblockiert%s\n\n", colorRed, colorReset)
						return unix.FAN_DENY
					default: // j, y, ja, yes, ""
						fmt.Printf("  → %serlaubt%s\n\n", colorGreen, colorReset)
						return unix.FAN_ALLOW
					}
				})
				if alreadyCached {
					if response == unix.FAN_ALLOW {
						fmt.Printf("  → %serlaubt (PID %d bereits bestätigt)%s\n\n", colorGreen, event.Pid, colorReset)
					} else {
						fmt.Printf("  → %sblockiert (PID %d bereits abgelehnt)%s\n\n", colorRed, event.Pid, colorReset)
					}
				}
			}

			// Send the response back to the kernel
			resp := unix.FanotifyResponse{
				Fd:       event.Fd,
				Response: response,
			}
			respBytes := (*[unsafe.Sizeof(resp)]byte)(unsafe.Pointer(&resp))
			err := writeFanotifyResponse(fd, respBytes[:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "response write error: %v\n", err)
			}

			// Close the event fd
			unix.Close(int(event.Fd))

			offset += int(event.Event_len)
		}
	}
}

// resolveDecision returns a cached allow/deny for pid if already decided,
// otherwise calls prompt() to get the user's decision and stores it.
func resolveDecision(pid int32, cache map[int32]uint32, prompt func() uint32) uint32 {
	if response, ok := cache[pid]; ok {
		return response
	}
	response := prompt()
	cache[pid] = response
	return response
}

func writeFanotifyResponse(fd int, data []byte) error {
	_, err := unix.Write(fd, data)
	return err
}

func resolveFilePath(fd int32) string {
	link := fmt.Sprintf("/proc/self/fd/%d", fd)
	path, err := os.Readlink(link)
	if err != nil {
		return fmt.Sprintf("(fd=%d, Pfad nicht auflösbar)", fd)
	}
	return path
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
