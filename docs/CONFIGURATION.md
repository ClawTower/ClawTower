# ClawAV Configuration Reference

ClawAV uses a TOML configuration file, typically located at `/etc/clawav/config.toml`.

Most sections use `#[serde(default)]` — missing sections gracefully fall back to defaults. However, **five sections are required** and must be present in the config file: `[general]`, `[slack]`, `[auditd]`, `[network]`, and `[scans]`. All other sections (`[falco]`, `[samhain]`, `[api]`, `[proxy]`, `[policy]`, `[secureclaw]`, `[netpolicy]`, `[ssh]`, `[sentinel]`, `[auto_update]`) are optional and have sensible defaults.

---

## Table of Contents

- [`[general]`](#general)
- [`[slack]`](#slack)
- [`[auditd]`](#auditd)
- [`[network]`](#network)
- [`[falco]`](#falco)
- [`[samhain]`](#samhain)
- [`[ssh]`](#ssh)
- [`[api]`](#api)
- [`[scans]`](#scans)
- [`[proxy]`](#proxy)
- [`[policy]`](#policy)
- [`[secureclaw]`](#secureclaw)
- [`[netpolicy]`](#netpolicy)
- [`[sentinel]`](#sentinel)
- [`[auto_update]`](#auto_update)

---

## `[general]`

**Struct:** `GeneralConfig`

Controls which users are monitored and the global alert threshold.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `watched_user` | `Option<String>` | `None` | Single UID to monitor (backward compat; prefer `watched_users`) |
| `watched_users` | `Vec<String>` | `[]` | List of **numeric UIDs** to monitor (e.g., `["1000"]`, not usernames — these match against auditd's `uid=` and `auid=` fields) |
| `watch_all_users` | `bool` | `false` | If `true`, monitor all users regardless of `watched_users` |
| `min_alert_level` | `String` | *(required)* | Minimum severity: `"info"`, `"warning"`, or `"critical"` |
| `log_file` | `String` | *(required)* | Path to ClawAV's own log file |

**User resolution logic** (`effective_watched_users()`):
- If `watch_all_users = true` → monitor everyone
- Otherwise merges `watched_user` + `watched_users` into a single list
- If resulting list is empty → monitor everyone

```toml
[general]
watched_users = ["1000"]   # Numeric UID, not username (find with: id -u openclaw)
watch_all_users = false
min_alert_level = "info"
log_file = "/var/log/clawav/clawav.log"
```

> ⚠️ **Common mistake:** Using usernames (e.g., `"openclaw"`) instead of numeric UIDs (e.g., `"1000"`). ClawAV matches against auditd's `uid=` and `auid=` fields, which are numeric. Find your user's UID with `id -u <username>`.

---

## `[slack]`

**Struct:** `SlackConfig`

Slack incoming webhook notifications with failover support.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `Option<bool>` | `None` | Explicitly enable/disable. `None` = enabled if `webhook_url` is set |
| `webhook_url` | `String` | *(required)* | Primary incoming webhook URL |
| `backup_webhook_url` | `String` | `""` | Failover webhook if primary fails |
| `channel` | `String` | *(required)* | Slack channel name (e.g., `"#security"`) |
| `min_slack_level` | `String` | *(required)* | Minimum severity to send to Slack |
| `heartbeat_interval` | `u64` | `3600` | Seconds between health heartbeats (0 = disabled) |

```toml
[slack]
enabled = true
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"
backup_webhook_url = ""
channel = "#security"
min_slack_level = "warning"
heartbeat_interval = 3600
```

---

## `[auditd]`

**Struct:** `AuditdConfig`

Linux audit log monitoring (syscall events).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | *(required)* | Enable auditd log tailing |
| `log_path` | `String` | *(required)* | Path to audit log (typically `/var/log/audit/audit.log`) |

```toml
[auditd]
enabled = true
log_path = "/var/log/audit/audit.log"
```

---

## `[network]`

**Struct:** `NetworkConfig`

Network/iptables log monitoring.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | *(required)* | Enable network log monitoring |
| `log_path` | `String` | *(required)* | Path to syslog (for file-based source) |
| `log_prefix` | `String` | *(required)* | Iptables log prefix to match (e.g., `"CLAWAV_NET"`) |
| `source` | `String` | `"auto"` | Log source: `"auto"`, `"journald"`, or `"file"` |
| `allowlisted_cidrs` | `Vec<String>` | RFC1918 + multicast + loopback | CIDR ranges to never alert on |
| `allowlisted_ports` | `Vec<u16>` | `[443, 53, 123, 5353]` | Ports to never alert on |

**Default CIDRs:** `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `169.254.0.0/16`, `127.0.0.0/8`, `224.0.0.0/4`

```toml
[network]
enabled = true
log_path = "/var/log/syslog"
log_prefix = "CLAWAV_NET"
source = "auto"
allowlisted_cidrs = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
allowlisted_ports = [443, 53, 123, 5353]
```

---

## `[falco]`

**Struct:** `FalcoConfig`

Falco eBPF syscall monitoring integration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable Falco log tailing |
| `log_path` | `String` | `"/var/log/falco/falco_output.jsonl"` | Path to Falco JSON log |

```toml
[falco]
enabled = false
log_path = "/var/log/falco/falco_output.jsonl"
```

---

## `[samhain]`

**Struct:** `SamhainConfig`

Samhain file integrity monitoring integration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable Samhain log tailing |
| `log_path` | `String` | `"/var/log/samhain/samhain.log"` | Path to Samhain log |

```toml
[samhain]
enabled = false
log_path = "/var/log/samhain/samhain.log"
```

---

## `[ssh]`

**Struct:** `SshConfig`

SSH login event monitoring via journald.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable SSH login monitoring |

```toml
[ssh]
enabled = true
```

---

## `[api]`

**Struct:** `ApiConfig`

HTTP REST API server for external integrations.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable the API server |
| `bind` | `String` | `"0.0.0.0"` | Bind address |
| `port` | `u16` | `18791` | Listen port |

**Endpoints:** `/api/status`, `/api/alerts`, `/api/health`, `/api/security`

```toml
[api]
enabled = false
bind = "0.0.0.0"
port = 18791
```

---

## `[scans]`

**Struct:** `ScansConfig`

Periodic security scanner configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interval` | `u64` | *(required)* | Seconds between scan cycles |

```toml
[scans]
interval = 300
```

---

## `[proxy]`

**Struct:** `ProxyConfig`

API key vault proxy with DLP scanning.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable the proxy server |
| `bind` | `String` | `"127.0.0.1"` | Bind address |
| `port` | `u16` | `18790` | Listen port |
| `key_mapping` | `Vec<KeyMapping>` | `[]` | Virtual→real key mappings |
| `dlp` | `DlpConfig` | `{ patterns: [] }` | DLP scanning configuration |

### `[[proxy.key_mapping]]`

**Struct:** `KeyMapping`

| Field | Type | Description |
|-------|------|-------------|
| `virtual_key` | `String` | Virtual key the agent uses (alias: `virtual`) |
| `real` | `String` | Actual API key sent upstream |
| `provider` | `String` | `"anthropic"` (x-api-key) or `"openai"` (Bearer token) |
| `upstream` | `String` | Upstream API base URL |

### `[[proxy.dlp.patterns]]`

**Struct:** `DlpPattern`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `String` | Pattern name for logging |
| `regex` | `String` | Regex pattern to match |
| `action` | `String` | `"block"` (reject request) or `"redact"` (replace with `[REDACTED]`) |

```toml
[proxy]
enabled = false
bind = "127.0.0.1"
port = 18790

[[proxy.key_mapping]]
virtual_key = "vk-anthropic-001"
real = "sk-ant-api03-REAL"
provider = "anthropic"
upstream = "https://api.anthropic.com"

[[proxy.dlp.patterns]]
name = "ssn"
regex = "\\b\\d{3}-\\d{2}-\\d{4}\\b"
action = "block"

[[proxy.dlp.patterns]]
name = "credit-card"
regex = "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"
action = "redact"

[[proxy.dlp.patterns]]
name = "aws-key"
regex = "AKIA[0-9A-Z]{16}"
action = "block"
```

---

## `[policy]`

**Struct:** `PolicyConfig`

YAML policy engine for detection rules (distinct from clawsudo enforcement).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable policy evaluation |
| `dir` | `String` | `"./policies"` | Directory containing `.yaml`/`.yml` policy files |

Files named `clawsudo*.yaml` are automatically skipped in the detection pipeline.

```toml
[policy]
enabled = true
dir = "./policies"
```

---

## `[secureclaw]`

**Struct:** `SecureClawConfig`

Vendor threat pattern engine loading JSON databases.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable SecureClaw pattern matching |
| `vendor_dir` | `String` | `"./vendor/secureclaw/secureclaw/skill/configs"` | Path to vendor JSON pattern files |

**Expected files in `vendor_dir`:**
- `injection-patterns.json`
- `dangerous-commands.json`
- `privacy-rules.json`
- `supply-chain-ioc.json`

```toml
[secureclaw]
enabled = false
vendor_dir = "./vendor/secureclaw/secureclaw/skill/configs"
```

---

## `[netpolicy]`

**Struct:** `NetPolicyConfig`

Network policy enforcement (allowlist/blocklist).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable network policy |
| `mode` | `String` | `"blocklist"` | `"allowlist"` (deny all except listed) or `"blocklist"` (allow all except listed) |
| `allowed_hosts` | `Vec<String>` | `[]` | Hosts allowed in allowlist mode (supports `*.suffix` wildcards) |
| `allowed_ports` | `Vec<u16>` | `[80, 443, 53]` | Ports allowed in allowlist mode |
| `blocked_hosts` | `Vec<String>` | `[]` | Hosts blocked in blocklist mode (supports `*.suffix` wildcards) |

```toml
[netpolicy]
enabled = false
mode = "blocklist"
allowed_hosts = ["api.anthropic.com", "*.openai.com", "github.com"]
allowed_ports = [80, 443, 53]
blocked_hosts = ["evil.com", "*.malware.net"]
```

---

## `[sentinel]`

**Struct:** `SentinelConfig`

Real-time file integrity monitoring via inotify.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable sentinel file watching |
| `watch_paths` | `Vec<WatchPathConfig>` | 3 default paths (see below) | Paths to monitor |
| `quarantine_dir` | `String` | `"/etc/clawav/quarantine"` | Where quarantined files are stored |
| `shadow_dir` | `String` | `"/etc/clawav/sentinel-shadow"` | Where shadow copies are stored |
| `debounce_ms` | `u64` | `200` | Milliseconds to debounce filesystem events |
| `scan_content` | `bool` | `true` | Run SecureClaw pattern scan on changed file contents |
| `max_file_size_kb` | `u64` | `1024` | Maximum file size (KB) for content scanning |

### `[[sentinel.watch_paths]]`

**Struct:** `WatchPathConfig`

| Field | Type | Description |
|-------|------|-------------|
| `path` | `String` | Absolute path to the file or directory to watch |
| `patterns` | `Vec<String>` | Glob patterns for matching (e.g., `["*"]` for all) |
| `policy` | `WatchPolicy` | `"protected"` or `"watched"` |

**Policies:**
- **`protected`**: On change → quarantine current file, restore from shadow copy, send Critical alert
- **`watched`**: On change → update shadow copy, send Info alert with diff

**Default watch paths:**
1. `SOUL.md` → protected
2. `AGENTS.md` → protected
3. `MEMORY.md` → watched

```toml
[sentinel]
enabled = true
quarantine_dir = "/etc/clawav/quarantine"
shadow_dir = "/etc/clawav/sentinel-shadow"
debounce_ms = 200
scan_content = true
max_file_size_kb = 1024

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/SOUL.md"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/AGENTS.md"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/MEMORY.md"
patterns = ["*"]
policy = "watched"
```

---

## `[auto_update]`

**Struct:** `AutoUpdateConfig`

Background auto-updater checking GitHub releases.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable automatic update checks |
| `interval` | `u64` | `300` | Seconds between update checks |

The auto-updater downloads new binaries with SHA-256 checksum verification (required) and Ed25519 signature verification (if `.sig` asset exists). Performs the `chattr -i` → replace → `chattr +i` → restart dance.

```toml
[auto_update]
enabled = true
interval = 300
```

---

## See Also

- [SENTINEL.md](SENTINEL.md) — Deep dive into `[sentinel]` configuration and behavior
- [ALERT-PIPELINE.md](ALERT-PIPELINE.md) — How `min_alert_level` and `min_slack_level` affect alert routing
- [POLICIES.md](POLICIES.md) — YAML policy format for `[policy]` directory
- [SECURITY-SCANNERS.md](SECURITY-SCANNERS.md) — What the `[scans]` interval controls
- [CLAWSUDO-AND-POLICY.md](CLAWSUDO-AND-POLICY.md) — `[proxy]` DLP configuration and admin key details
- [INSTALL.md](INSTALL.md) — Installation steps that create the default config

---

## Complete Example

```toml
[general]
watched_users = ["1000"]  # Numeric UID (find with: id -u openclaw)
min_alert_level = "info"
log_file = "/var/log/clawav/clawav.log"

[slack]
enabled = true
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"
backup_webhook_url = ""
channel = "#security"
min_slack_level = "warning"
heartbeat_interval = 3600

[auditd]
enabled = true
log_path = "/var/log/audit/audit.log"

[network]
enabled = true
log_path = "/var/log/syslog"
log_prefix = "CLAWAV_NET"
source = "auto"
allowlisted_cidrs = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4"]
allowlisted_ports = [443, 53, 123, 5353]

[falco]
enabled = false
log_path = "/var/log/falco/falco_output.jsonl"

[samhain]
enabled = false
log_path = "/var/log/samhain/samhain.log"

[ssh]
enabled = true

[api]
enabled = false
bind = "0.0.0.0"
port = 18791

[scans]
interval = 300

[proxy]
enabled = false
bind = "127.0.0.1"
port = 18790

[policy]
enabled = true
dir = "./policies"

[secureclaw]
enabled = false
vendor_dir = "./vendor/secureclaw/secureclaw/skill/configs"

[netpolicy]
enabled = false
mode = "blocklist"
blocked_hosts = []

[sentinel]
enabled = true
quarantine_dir = "/etc/clawav/quarantine"
shadow_dir = "/etc/clawav/sentinel-shadow"
debounce_ms = 200
scan_content = true
max_file_size_kb = 1024

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/SOUL.md"
patterns = ["*"]
policy = "protected"

[auto_update]
enabled = true
interval = 300
```
