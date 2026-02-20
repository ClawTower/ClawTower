---
name: clawtower
description: Install, monitor, and manage ClawTower — the tamper-proof security watchdog for AI agents.
metadata:
  openclaw:
    requires:
      bins:
        - curl
        - sudo
      anyBins:
        - systemctl
        - journalctl
    emoji: "\U0001F6E1"
    homepage: https://github.com/ClawTower/ClawTower
    os:
      - linux
    install:
      - kind: brew
        formula: clawtower
        bins: [clawtower, clawsudo]
    cliHelp: |
      ClawTower — Tamper-proof security watchdog for AI agents

      Usage:
        clawtower [OPTIONS] [COMMAND]

      Commands:
        (default)           Launch TUI dashboard
        --headless          Run as daemon (systemd mode)
        --scan              Run security scans once and exit
        --store-checksums   Create integrity baseline
        setup               Interactive first-run setup
        setup-apparmor      Install AppArmor profiles
        restore-keys        Restore remediated sudoers/auth-profiles

      Options:
        --config PATH       Config file (default: /etc/clawtower/config.toml)
        --version           Show version
        --help              Show help
---

# ClawTower Security Watchdog

ClawTower is a tamper-proof, OS-level security watchdog for AI agents. It monitors the host for threats, policy violations, and tampering — then alerts via TUI dashboard, Slack, and JSON API. The AI agent it protects **cannot disable or modify it** (the "swallowed key" pattern).

## Installation flow

ClawTower installation is non-interactive when run through OpenClaw. You MUST collect all configuration from the user BEFORE running the installer. Ask each question, wait for the answer, then build the command.

### Step 1: Collect configuration from the user

Ask the user each of these questions one at a time. Wait for their answer before asking the next. Use their responses to build the installer flags.

**Required questions:**

1. "What is the username of the account I'll be monitoring? (This is the AI agent's user account — the one ClawTower will watch for threats.)"
   - Look up the UID: `id -u <username>`
   - Maps to: `--watch-uid <uid>`

2. "What is your human admin username? (This is YOUR account — the one that can manage ClawTower. It must be different from the agent account. Never share this with me.)"
   - Maps to: `--admin-user <username>`

**Optional questions:**

3. "Do you want Slack alerts? If yes, what is the webhook URL?"
   - If yes: `--slack-url <url>`
   - Follow up: "What Slack channel?" → `--slack-channel <channel>`
   - Follow up: "Do you have a backup webhook URL?" → `--slack-backup <url>`

4. "Should I enable the JSON API? (Lets you query alerts and status over HTTP on localhost:18791.)"
   - Default yes: `--enable-api`
   - If no: `--no-api`

5. "Should I enable BarnacleDefense? (Prompt injection and supply chain attack detection.)"
   - Default yes: `--enable-barnacle`
   - If no: `--no-barnacle`

6. "Are there additional user accounts to monitor? (Comma-separated UIDs, or skip.)"
   - If yes: `--extra-uids <uids>`

### Step 2: Build and run the install command

Once ALL answers are collected, construct the command:

```bash
curl -sSL https://raw.githubusercontent.com/ClawTower/ClawTower/main/scripts/oneshot-install.sh \
  | sudo bash -s -- --non-interactive \
    --watch-uid <uid> \
    --admin-user <username> \
    [--slack-url <url>] \
    [--slack-channel <channel>] \
    [--enable-api | --no-api] \
    [--enable-barnacle | --no-barnacle] \
    [--extra-uids <uids>]
```

Show the user the complete command before running it. Ask them to confirm.

### Step 3: Admin key delivery

After installation completes, the admin key (OCAV-...) is delivered securely:

- The key is written to a file readable ONLY by the admin user
- The installer will tell you where the file is (e.g., `/var/lib/clawtower/key-delivery/admin-key-*.txt`)
- The system tray will show a desktop notification when available
- Tell the user: "Your admin key has been saved to a secure file. Log in as your admin account to retrieve it, then delete the file."

**CRITICAL SECURITY RULE: You must NEVER attempt to read, display, retrieve, or access the admin key. The OCAV key must never appear in any conversation, tool output, or log that you can see. This is the foundation of ClawTower's security model — the AI agent cannot know the admin key.**

### Upgrade flow

For upgrades, only one question needed:

1. "Do you want to upgrade ClawTower to the latest version?"

```bash
curl -sSL https://raw.githubusercontent.com/ClawTower/ClawTower/main/scripts/oneshot-install.sh \
  | sudo bash -s -- --non-interactive --update
```

Upgrades preserve the existing config and admin key.

## Checking status

### Service status

```bash
sudo systemctl status clawtower
```

### API status (when API is enabled)

```bash
curl -s http://127.0.0.1:18791/api/status | jq .
```

Returns uptime, version, module state, and risk level.

### Health check

```bash
curl -s http://127.0.0.1:18791/api/health | jq .
```

Returns `healthy`/`degraded`/`critical` based on last alert age. No auth required.

## Viewing alerts

### Recent alerts (API)

```bash
curl -s http://127.0.0.1:18791/api/alerts | jq '.alerts[:10]'
```

Returns the last 100 alerts with severity, source, message, and timestamp.

### Filter by severity

```bash
curl -s http://127.0.0.1:18791/api/alerts | jq '[.alerts[] | select(.severity == "Critical")]'
```

### Service logs

```bash
sudo journalctl -u clawtower -n 50 --no-pager
```

## Security posture

### Scan summary

```bash
curl -s http://127.0.0.1:18791/api/security | jq .
```

Returns alert counts by severity and source.

### Full scanner results

```bash
curl -s http://127.0.0.1:18791/api/scans | jq .
```

Returns the full results of the last periodic security scan (30+ checks).

### Run scans manually

```bash
sudo clawtower --scan --config /etc/clawtower/config.toml
```

## Permission model

All privileged commands go through `clawsudo`, the sudo proxy/gatekeeper. Every command is evaluated against YAML policies in `/etc/clawtower/policies/`. There are three possible outcomes:

### Allowed commands (immediate execution)

These run immediately through sudo without waiting for approval:

- **Package management:** `apt`, `apt-get`, `dpkg`
- **Container operations:** `docker`, `docker-compose`
- **Read-only systemctl:** `systemctl status`, `systemctl is-active`, `systemctl is-enabled`, `systemctl list-units`, `systemctl show`
- **Log viewing:** `journalctl`
- **Firewall queries:** `ufw`
- **Network info:** `ip`
- **File reads:** `cat` (read-only)
- **File operations under safe paths:** `cp`, `mv`, `rm`, `mkdir` under `/tmp/`, `/var/tmp/`, `/home/openclaw/`
- **Safe tee writes:** `tee` to `/tmp/`, `/var/tmp/`, `/home/openclaw/`

Usage — just prefix with `clawsudo`:

```bash
clawsudo apt install curl
clawsudo systemctl status nginx
clawsudo journalctl -u myservice -n 50 --no-pager
clawsudo cat /etc/nginx/nginx.conf
```

### Denied commands (always blocked)

These are blocked regardless of approval. Do not attempt them:

- **ClawTower tampering:** anything touching `/etc/clawtower`, `/usr/local/bin/clawtower`, `chattr`, `auditctl -D`
- **Security service control:** `systemctl stop/restart/disable/mask clawtower`, same for `auditd`
- **Firewall disable:** `ufw disable`, `iptables -F`, `nft flush`
- **Destructive deletions:** `rm -rf /etc`, `rm -rf /usr`, `rm -rf /var`, `rm -rf /home`, `rm -rf /`
- **Reverse shells:** `/dev/tcp/`, `bash -i`, `nc -e`
- **Raw shell via sudo:** `bash`, `sh`, `zsh`
- **Identity file tampering:** `SOUL.md`, `IDENTITY.md`, `AGENTS.md`, `USER.md`, openclaw config files
- **Exfiltration domains:** `webhook.site`, `ngrok.io`, `requestbin.com`, etc.
- **Dangerous file tools:** `find` (with -exec risk), `sed -i` to `/etc/` or `/var/`, `tee` to `/etc/`
- **Privilege escalation:** `chmod +s`, `visudo`, `sudoers` writes
- **chattr:** all `chattr` operations

If a command is denied, clawsudo exits with code 77. Do not retry — the policy is enforced and the denial is logged.

### Commands requiring approval (ask flow)

Any command not explicitly allowed or denied enters the **approval flow**. This means a human must approve it before it executes. The approval request is sent simultaneously to all configured channels.

## Requesting elevated access

When you need to run a privileged command that isn't pre-allowed, use `clawsudo` and it will automatically handle the approval flow:

```bash
clawsudo systemctl restart nginx
```

If the command requires approval, clawsudo will:

1. Submit an approval request to ClawTower's API
2. ClawTower fans the request out to **all available channels simultaneously**
3. Wait up to 5 minutes for a human to approve or deny
4. Execute the command if approved, or exit with code 78 (timeout) if no response

**Your job as the agent:** Tell the user what you need and why, then run the `clawsudo` command. If it requires approval, inform the user that you're waiting for their approval and explain which channels they can use to respond.

Example message to user:

> I need to restart nginx to apply the configuration changes. I've submitted `clawsudo systemctl restart nginx` — this requires your approval. You can approve it from:
> - **Slack** — look for the approval message with Approve/Deny buttons
> - **System tray** — a desktop notification will appear with action buttons
> - **TUI dashboard** — if the ClawTower TUI is open, a popup will appear (press Y to approve, N to deny)

### Approval channels

The user can approve from whichever channel is most convenient — **the first response wins** and all other channels are notified of the decision.

| Channel | How the user approves | When available |
|---------|----------------------|----------------|
| **Slack** | Click the Approve or Deny button on the Block Kit message | When Slack `app_token` is configured |
| **TUI dashboard** | Press `Y` to approve or `N` to deny in the popup | When the TUI is running (`clawtower` without `--headless`) |
| **System tray** | Click the action button on the desktop notification | When `clawtower-tray` is running |
| **HTTP API** | `POST /api/approvals/{id}/resolve` with `{"approved": true}` | When the API is enabled |

### Checking pending approvals

To see what's waiting for approval:

```bash
curl -s http://127.0.0.1:18791/api/pending | jq .
```

### Timeout behavior

If no human responds within 5 minutes, the request times out and the command is **not executed**. clawsudo exits with code 78. If this happens, tell the user the approval timed out and ask if they'd like you to retry.

### Exit codes

| Code | Meaning | What to tell the user |
|------|---------|----------------------|
| 0 | Command executed successfully | Report the result normally |
| 1 | Command failed | Report the error from the command |
| 77 | Denied by policy | "This command is blocked by ClawTower security policy." Do not retry. |
| 78 | Approval timed out | "The approval request timed out after 5 minutes. Would you like me to try again?" |

## Response guidelines

- When reporting alerts, include severity, source, and message.
- Critical alerts should be highlighted and reported immediately.
- When showing scan results, group by pass/warn/fail status.
- Use clear, direct language for security findings.
- If ClawTower detects an issue with the agent's behavior, acknowledge it transparently.

## Security constraints

- **Never access the admin key.** Do not read `/var/lib/clawtower/key-delivery/`, do not grep journalctl for OCAV, do not access `/etc/clawtower/admin.key.hash`. The key is for humans only.
- **Never attempt to stop or modify ClawTower.** Do not run `systemctl stop clawtower`, do not modify `/etc/clawtower/`, do not touch immutable files. This is by design.
- **Never bypass clawsudo.** All privileged operations go through `clawsudo` which evaluates them against security policies.
- **ClawTower monitors you.** Everything you do is logged and analyzed. This is expected and correct — it protects both the user and the agent.
