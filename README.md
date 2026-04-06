# suspicious

> **Warning: Proof of concept.** This tool is experimental and may contain security vulnerabilities despite best efforts. Do not rely on it as your only line of defense. Use at your own risk.

A Linux file-access monitoring daemon that intercepts file reads in real time using the kernel's **fanotify** API. When a process touches a watched path, an operator is prompted interactively (allow / deny / whitelist) before the kernel returns control to the calling process.

```
─── Access detected ──── 2026-04-06 14:32:01
  File:    /home/user/.ssh/id_ed25519
  Process: cat (PID 12345)
  Cmd:     cat /home/user/.ssh/id_ed25519
  Parents: zsh ← ghostty ← systemd
  Action:  OPEN
  Allow? [Y/n/w=chain whitelist]:
```

## How it works

The daemon holds a fanotify file descriptor and must respond to each kernel permission event before the accessing process is unblocked. It runs as a **headless systemd service** using only `CAP_SYS_ADMIN` (not full root). A separate CLI tool (`suspicious attach`) connects over a Unix socket to display prompts and send decisions.

If no CLI is attached when an event arrives, the daemon **auto-denies** after a configurable timeout (default: 5 s).

## Requirements

- Linux kernel ≥ 5.1
- Go ≥ 1.21 (to build)
- `CAP_SYS_ADMIN` capability (or root) to run the daemon

## Build

```bash
go build -o suspicious .
```

## Quick start (without systemd)

```bash
# Terminal 1 — start the daemon (needs CAP_SYS_ADMIN / root)
sudo SUSPICIOUS_SOCKET=/tmp/suspicious.sock suspicious config.yaml

# Terminal 2 — attach the interactive CLI (no root needed once socket exists)
SUSPICIOUS_SOCKET=/tmp/suspicious.sock suspicious attach
```

## Install as a systemd service

### 1. Create the service user and group

```bash
sudo useradd -r -s /sbin/nologin suspicious
```

Add every user who needs to run `suspicious attach` to the `suspicious` group:

```bash
sudo usermod -aG suspicious $USER
# Log out and back in for the group change to take effect
```

### 2. Install the binary

```bash
sudo cp suspicious /usr/local/bin/suspicious
sudo chmod 755 /usr/local/bin/suspicious
```

### 3. Create the config

```bash
sudo mkdir -p /etc/suspicious
sudo cp config.yaml /etc/suspicious/config.yaml
sudo chown -R suspicious:suspicious /etc/suspicious
sudo chmod 640 /etc/suspicious/config.yaml
```

### 4. Install and enable the service

```bash
sudo cp suspicious.service /etc/systemd/system/suspicious.service
sudo systemctl daemon-reload
sudo systemctl enable --now suspicious
```

Check status:

```bash
systemctl status suspicious
journalctl -u suspicious -f
```

### 5. Attach the CLI

```bash
suspicious attach
# defaults to /run/suspicious/events.sock
```

The socket is created at `/run/suspicious/events.sock` (mode `0660`, group `suspicious`). Any user in the `suspicious` group can attach.

## Configuration

`/etc/suspicious/config.yaml`:

```yaml
# Paths to watch. Each entry is a directory or file.
paths:
  - path: /home/user/.ssh

  - path: /home/user/.kube
    # Processes whose full parent chain matches any entry are auto-allowed.
    # Entries are matched as a prefix of the child→root process name list.
    allow_parent_chains:
      - kubectl,zsh,ghostty,systemd

  - path: /home/user/.gnupg
    # Specific executables that are always allowed (matched against /proc/<pid>/exe).
    allow_binaries:
      - /usr/bin/gpg
      - /usr/lib/gnupg/scdaemon

# Set to true to log all accesses without prompting (audit-only mode).
allow_all: false
```

### Parent chain whitelisting

When you press **`w`** in the CLI, the current process's full parent chain is appended to `allow_parent_chains` for that path and saved to the config file. The daemon picks it up immediately — no restart needed.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SUSPICIOUS_SOCKET` | `/run/suspicious/events.sock` | Unix socket path |
| `SUSPICIOUS_TIMEOUT` | `5s` | Auto-deny timeout when no CLI is attached |

## CLI prompt keys

| Key | Action |
|---|---|
| `y` / Enter | Allow this access |
| `n` | Deny this access |
| `w` | Allow and save parent chain to whitelist |

## Decision caching

Each unique `(PID, file path)` combination is decided once per daemon run. Subsequent accesses from the same process to the same file use the cached decision without prompting.

## Systemd unit reference

```ini
[Unit]
Description=suspicious - fanotify file access monitor
After=local-fs.target

[Service]
User=suspicious
Group=suspicious

# Only this capability is needed — not full root.
AmbientCapabilities=CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_SYS_ADMIN

# systemd creates /run/suspicious/ owned by the service user.
RuntimeDirectory=suspicious
RuntimeDirectoryMode=0750

ExecStart=/usr/local/bin/suspicious /etc/suspicious/config.yaml

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
SystemCallFilter=@system-service

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Running tests

```bash
# Unit tests (no root needed)
go test ./...

# Integration tests (require root + CAP_SYS_ADMIN)
sudo go test -tags integration -v ./...
```
