# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

`suspicious` is a Linux file-access monitoring daemon that uses the kernel's **fanotify** API (`FAN_OPEN_PERM` / `FAN_ACCESS_PERM`) to intercept and allow/deny file reads in real time. When a process touches a watched path, the daemon prompts the operator interactively (j/n/a) before the kernel returns control to the calling process. The binary must run as root (requires `CAP_SYS_ADMIN`).

## Commands

```bash
# Build
go build -o suspicious .

# Run (needs root)
sudo ./suspicious [config.yaml]

# Unit tests (no root needed)
go test ./...

# Integration tests (need root + CAP_SYS_ADMIN)
sudo go test -tags integration -v ./...

# Single test
go test -run TestResolveDecision_CachesOnSecondAccessSameFile ./...
```

## Architecture

All code lives in `package main`. Key files:

| File | Responsibility |
|---|---|
| `main.go` | fanotify init/mark loop, event read loop, interactive prompt, `resolveDecision` cache |
| `config.go` | `loadConfig` — parses `config.yaml`, expands env vars |
| `process.go` | `resolveProcessTree` — walks `/proc/<pid>/status` PPid chain to build child→root ancestry |
| `config.yaml` | Example config: `paths` list + `allow_all` toggle |

### PathConfig fields

Each entry under `paths` supports:
- `path` (string) — directory or file to watch
- `allow_binaries` (list) — executable paths auto-allowed without prompting
- `allow_parent_chains` (list) — comma-separated ancestor process name chains that are auto-allowed (e.g. `git,lazygit,zsh`); matched as a prefix of the process tree from child→root

### Decision caching

`resolveDecision` (in `main.go`) caches allow/deny per `(pid, path)` pair in a `map[pidFileKey]uint32`. Each unique `(pid, filePath)` combination prompts exactly once per run. `autoAllow` (`allow_all: true` or pressing `a`) bypasses prompting entirely and logs-only.

### fanotify flow

1. `FanotifyInit` with `FAN_CLASS_CONTENT` (required for permission events)
2. `FanotifyMark` per configured path; directories also get `FAN_EVENT_ON_CHILD`
3. Read loop blocks on the fanotify fd, processes `FanotifyEventMetadata` structs
4. Each event fd is resolved via `/proc/self/fd/<fd>` symlink → absolute path
5. `FanotifyResponse` (ALLOW or DENY) must be written back before the event fd is closed

### Test structure

- `config_test.go`, `config_chain_test.go`, `process_test.go`, `decision_test.go` — unit tests, no root needed
- `integration_test.go` — build tag `integration`; spawns the real binary, drives it via stdin, asserts output contains expected strings (German UI text like `"Zugriff erkannt"`, `"blockiert"`)
