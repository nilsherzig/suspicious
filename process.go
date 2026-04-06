package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type ProcessInfo struct {
	Pid  int32
	Name string
	Cmd  string
}

func resolveProcess(pid int32) (name string, cmdline string) {
	commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		name = "(unbekannt)"
	} else {
		name = strings.TrimSpace(string(commBytes))
	}

	cmdBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		cmdline = "(nicht lesbar)"
	} else {
		cmdline = strings.ReplaceAll(string(cmdBytes), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
		if cmdline == "" {
			cmdline = "(leer)"
		}
	}

	return name, cmdline
}

// resolveProcessTree walks the parent chain from pid up to PID 1 (or until
// the parent is unreachable) and returns the ancestry ordered child→root.
func resolveProcessTree(pid int32) []ProcessInfo {
	var tree []ProcessInfo
	seen := make(map[int32]bool)

	current := pid
	for current > 0 {
		if seen[current] {
			break
		}
		seen[current] = true

		name, cmd := resolveProcess(current)
		if name == "(unbekannt)" && current != pid {
			break
		}
		tree = append(tree, ProcessInfo{Pid: current, Name: name, Cmd: cmd})

		if current == 1 {
			break
		}

		parent, err := readPPid(current)
		if err != nil || parent <= 0 {
			break
		}
		current = parent
	}

	return tree
}

// readPPid reads the parent PID from /proc/<pid>/status.
func readPPid(pid int32) (int32, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("unexpected PPid line: %q", line)
			}
			v, err := strconv.ParseInt(fields[1], 10, 32)
			return int32(v), err
		}
	}
	return 0, fmt.Errorf("PPid not found in /proc/%d/status", pid)
}
