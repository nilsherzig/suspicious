package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
	watchPath := flag.String("path", "", "file or directory to watch")
	allowAll := flag.Bool("allow-all", false, "log only, allow everything without prompting")
	flag.Parse()

	if *watchPath == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -path /pfad/zur/datei [-allow-all]\n", os.Args[0])
		os.Exit(1)
	}

	// Verify path exists
	info, err := os.Stat(*watchPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fehler: %s existiert nicht: %v\n", *watchPath, err)
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

	// Mark the target with permission events
	mask := uint64(unix.FAN_OPEN_PERM | unix.FAN_ACCESS_PERM)
	if info.IsDir() {
		mask |= unix.FAN_EVENT_ON_CHILD
	}

	err = unix.FanotifyMark(fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, *watchPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fanotify_mark fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s%s[fanotify-guard]%s Überwache: %s%s%s\n", colorBold, colorCyan, colorReset, colorYellow, *watchPath, colorReset)
	if *allowAll {
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
	autoAllow := *allowAll
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

			// Resolve process info from PID
			procName, procCmdline := resolveProcess(event.Pid)

			// Determine event type
			eventType := describeEvent(event.Mask)

			// Print the event info
			fmt.Printf("%s%s─── Zugriff erkannt ───%s\n", colorBold, colorCyan, colorReset)
			fmt.Printf("  Datei:   %s%s%s\n", colorYellow, filePath, colorReset)
			fmt.Printf("  Prozess: %s%s%s (PID %d)\n", colorBold, procName, colorReset, event.Pid)
			fmt.Printf("  Cmd:     %s\n", procCmdline)
			fmt.Printf("  Aktion:  %s\n", eventType)

			var response uint32
			if autoAllow {
				response = unix.FAN_ALLOW
				fmt.Printf("  → %sautomatisch erlaubt%s\n\n", colorGreen, colorReset)
			} else {
				fmt.Printf("  Erlauben? [j/n/a]: ")
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(strings.ToLower(input))

				switch input {
				case "j", "y", "ja", "yes", "":
					response = unix.FAN_ALLOW
					fmt.Printf("  → %serlaubt%s\n\n", colorGreen, colorReset)
				case "a", "all", "alle":
					response = unix.FAN_ALLOW
					autoAllow = true
					fmt.Printf("  → %serlaubt (ab jetzt alles automatisch)%s\n\n", colorYellow, colorReset)
				default:
					response = unix.FAN_DENY
					fmt.Printf("  → %sblockiert%s\n\n", colorRed, colorReset)
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

func resolveProcess(pid int32) (name string, cmdline string) {
	// Read comm (short process name)
	commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		name = "(unbekannt)"
	} else {
		name = strings.TrimSpace(string(commBytes))
	}

	// Read full cmdline
	cmdBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		cmdline = "(nicht lesbar)"
	} else {
		// cmdline uses null bytes as separators
		cmdline = strings.ReplaceAll(string(cmdBytes), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
		if cmdline == "" {
			cmdline = "(leer)"
		}
	}

	return name, cmdline
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
