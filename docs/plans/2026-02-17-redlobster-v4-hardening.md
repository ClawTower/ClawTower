# Red Lobster v4 Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close all 3 bypassed flags and 1 finding from the Red Lobster v4 pentest, bringing detection from 3/6 to 6/6.

**Architecture:** Four parallel workstreams — each addresses one pentest gap. Changes are in Rust source (behavior detection, auditd parsing, sentinel config, API auth), shell scripts (auditd rules, iptables prefix fix), and config defaults. No cargo locally — push to GitHub, CI builds.

**Tech Stack:** Rust (tokio async), Linux auditd, iptables/nftables, inotify (sentinel)

**Constraints:** No `cargo` on this machine. Edit code, commit, push — CI builds and tests. Read `CLAUDE.md` at repo root before making changes.

---

## Workstream Summary

| # | Flag | Gap | Fix |
|---|------|-----|-----|
| 1 | EXFIL (Flag 1) | Only cp/tee detected for file copies | Expand auditd rules + behavior patterns for all copy methods |
| 2 | PERSIST (Flag 3) | crontab, timers, at, git hooks, npm, python undetected | Add sentinel watch paths + auditd rules for persistence dirs |
| 3 | ESCAPE (Flag 6) | Zero network alerts | Fix log prefix mismatch (OPENCLAWTOWER_NET → CLAWTOWER_NET) + add auditd connect() rules |
| 4 | API Auth (Flag 2) | Unauthenticated API on 0.0.0.0:18791 | Add bearer token auth + default bind to 127.0.0.1 |

---

## Task 1: Fix Network Monitoring (Flag 6 — ESCAPE)

**Root Cause:** `scripts/setup-iptables.sh` uses prefix `OPENCLAWTOWER_NET` but `config.rs` defaults to `CLAWTOWER_NET`. Network log lines never match the parser prefix.

**Files:**
- Modify: `scripts/setup-iptables.sh:9`

**Step 1: Fix the log prefix**

In `scripts/setup-iptables.sh`, line 9, change:
```bash
LOG_PREFIX="OPENCLAWTOWER_NET"
```
to:
```bash
LOG_PREFIX="CLAWTOWER_NET"
```

**Step 2: Commit**

```bash
git add scripts/setup-iptables.sh
git commit -m "fix: align iptables log prefix with config default (CLAWTOWER_NET)

Root cause of Flag 6 (ESCAPE) bypass — zero network alerts because
setup-iptables.sh used OPENCLAWTOWER_NET but config.rs expects CLAWTOWER_NET.
All iptables log lines were silently ignored by the network parser."
```

---

## Task 2: Add Auditd Connect() Monitoring (Flag 6 — ESCAPE backup)

**Why:** Even with iptables logging fixed, auditd-based connect() monitoring provides defense-in-depth for outbound connections. Currently, connect() detection only fires for runtime interpreters (python3, node). Need to catch ALL connect() syscalls by watched user.

**Files:**
- Modify: `src/auditd.rs` — add connect() audit rules to `REQUIRED_AUDIT_RULES` and enhance `event_to_alert()`

**Step 1: Add connect() audit rule**

In `src/auditd.rs`, add to `REQUIRED_AUDIT_RULES` array (after the existing credential read rules):

```rust
    // Network connect() monitoring for watched user (T6.1 — outbound escape detection)
    "-a always,exit -F arch=b64 -S connect -F uid=1000 -F success=1 -k clawtower_net_connect",
```

**Step 2: Add connect() audit key handler in `event_to_alert()`**

In `src/auditd.rs`, in the `event_to_alert()` function, before the final `None`, add:

```rust
    // Network connect() detection via auditd (T6.1)
    if line.contains("key=\"clawtower_net_connect\"") || line.contains("key=clawtower_net_connect") {
        let exe = extract_field(line, "exe").unwrap_or("unknown");
        // Skip localhost connections and known-safe processes
        let is_safe = exe.contains("clawtower") || exe.contains("systemd") || exe.contains("dbus");
        if !is_safe {
            return Some(Alert::new(
                Severity::Warning,
                "auditd:net_connect",
                &format!("🌐 Outbound connect() by {}", exe),
            ));
        }
    }
```

**Step 3: Add test**

In `src/auditd.rs`, in the test module, add:

```rust
    #[test]
    fn test_connect_audit_key_detected() {
        let line = r#"type=SYSCALL msg=audit(1234567890.123:456): arch=c00000b7 syscall=203 success=yes exit=0 a0=3 a1=7fff123 a2=10 a3=0 items=0 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=1 comm="curl" exe="/usr/bin/curl" key="clawtower_net_connect""#;
        let watched_users = vec!["1000".to_string()];
        let alert = parse_audit_line(line, &watched_users);
        assert!(alert.is_some(), "connect() with clawtower_net_connect key should trigger alert");
        let alert = alert.unwrap();
        assert!(alert.source.contains("net_connect"));
    }
```

**Step 4: Commit**

```bash
git add src/auditd.rs
git commit -m "feat: add auditd connect() monitoring for outbound escape detection

Adds connect() syscall audit rule and handler for clawtower_net_connect key.
Defense-in-depth for Flag 6 (ESCAPE) — catches outbound connections even
without iptables LOG rules."
```

---

## Task 3: Expand Exfil Detection (Flag 1 — EXFIL)

**Root Cause:** Behavior engine only checks specific binary names (cp, tee) against file args. Methods like `cat file > copy`, `dd if=file`, `python3 -c "open(...)"`, `tar cf`, `sed 'w output'` don't match. The auditd credential read rules (`clawtower_cred_read` key) exist in code but the setup script (`setup-audit-rules.sh`) doesn't install them.

**Files:**
- Modify: `scripts/setup-audit-rules.sh` — add credential read watch rules
- Modify: `src/behavior.rs` — expand file copy detection patterns

**Step 1: Update auditd rules script**

Replace `scripts/setup-audit-rules.sh` content to include the credential read rules that are already defined in `REQUIRED_AUDIT_RULES` in `auditd.rs`:

Add after the existing rules in the heredoc:

```bash
# Credential file read monitoring (exfil detection)
-w /home/openclaw/.openclaw/agents/main/agent/auth-profiles.json -p r -k clawtower_cred_read
-w /home/openclaw/.aws/credentials -p r -k clawtower_cred_read
-w /home/openclaw/.aws/config -p r -k clawtower_cred_read
-w /home/openclaw/.ssh/id_ed25519 -p r -k clawtower_cred_read
-w /home/openclaw/.ssh/id_rsa -p r -k clawtower_cred_read
-w /home/openclaw/.openclaw/gateway.yaml -p r -k clawtower_cred_read
```

**Step 2: Expand behavior.rs file copy detection**

The current check at line ~787 only catches `cat, less, more, head, tail, xxd, base64, cp, scp`. Need to add more copy tools that the pentest used.

In `src/behavior.rs`, find the `CRITICAL_READ_PATHS` check and expand the binary list:

Change:
```rust
        if ["cat", "less", "more", "head", "tail", "xxd", "base64", "cp", "scp"].contains(&binary) {
```
To:
```rust
        if ["cat", "less", "more", "head", "tail", "xxd", "base64", "cp", "scp", "dd", "tar", "rsync", "sed", "tee"].contains(&binary) {
```

Also add `dd` special handling — `dd` uses `if=` syntax, not positional args:

After the `CRITICAL_READ_PATHS` binary check block, add:

```rust
        // dd special handling — uses if=<path> syntax
        if binary == "dd" {
            for arg in args.iter() {
                if arg.starts_with("if=") {
                    let path = &arg[3..];
                    for crit_path in CRITICAL_READ_PATHS {
                        if path.contains(crit_path) {
                            return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                        }
                    }
                    for recon_path in RECON_PATHS {
                        if path.contains(recon_path) {
                            return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
                        }
                    }
                }
            }
        }
```

**Step 3: Widen credential read auditd allowlist**

In `src/auditd.rs`, the credential read handler allowlists `exe.contains("node")` which is too broad — any Node.js process can read credentials undetected. Tighten to specific paths:

Change:
```rust
        let is_openclaw = exe.contains("openclaw") || exe.contains("node");
```
To:
```rust
        let is_openclaw = exe.contains("openclaw") || exe.contains("/usr/bin/node") || exe.contains("/usr/local/bin/node");
```

**Step 4: Add tests**

In `src/behavior.rs` test module:

```rust
    #[test]
    fn test_dd_reading_sensitive_file() {
        let event = make_exec_event(&["dd", "if=/etc/shadow", "of=/tmp/shadow"]);
        let result = classify_behavior(&event);
        assert!(result.is_some(), "dd reading /etc/shadow should be detected");
        assert_eq!(result.unwrap().1, Severity::Critical);
    }

    #[test]
    fn test_tar_reading_sensitive_dir() {
        let event = make_exec_event(&["tar", "cf", "/tmp/out.tar", "/home/user/.ssh/id_rsa"]);
        let result = classify_behavior(&event);
        assert!(result.is_some(), "tar on .ssh/id_rsa should be detected");
    }

    #[test]
    fn test_rsync_sensitive_file() {
        let event = make_exec_event(&["rsync", "/home/user/.aws/credentials", "/tmp/creds"]);
        let result = classify_behavior(&event);
        assert!(result.is_some(), "rsync on .aws/credentials should be detected");
    }
```

**Step 5: Commit**

```bash
git add scripts/setup-audit-rules.sh src/behavior.rs src/auditd.rs
git commit -m "feat: expand exfil detection — dd/tar/rsync/sed + auditd cred read rules

Closes Flag 1 (EXFIL) gaps:
- Expanded binary list for CRITICAL_READ_PATHS checks
- Added dd if= syntax special handling
- Added credential read auditd rules to setup script
- Tightened node allowlist in cred read handler"
```

---

## Task 4: Expand Persistence Detection (Flag 3 — PERSIST)

**Root Cause:** Sentinel only watches explicitly configured paths. The persistence dirs (crontab spool, at queue, systemd user units, git hooks, npm/Python hooks) aren't in the default sentinel config. Behavior.rs catches `crontab -e` and `at` binaries via EXECVE events, but the pentest likely used direct file writes (e.g., `echo ... > ~/.config/systemd/user/evil.timer`) which bypass command detection.

**Files:**
- Modify: `src/config.rs` — add persistence dirs to default sentinel watch_paths
- Modify: `src/sentinel.rs` — extend `is_persistence_critical()` for npm/Python persistence
- Modify: `src/behavior.rs` — add npm/Python sitecustomize patterns

**Step 1: Add persistence directories to default sentinel config**

In `src/config.rs`, in `impl Default for SentinelConfig`, add these `WatchPathConfig` entries to the `watch_paths` vec:

```rust
                // Persistence monitoring directories
                WatchPathConfig {
                    path: "/var/spool/cron/crontabs/".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Watched,
                },
                WatchPathConfig {
                    path: "/var/spool/at/".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Watched,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.config/systemd/user/".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Watched,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.config/autostart/".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Watched,
                },
                WatchPathConfig {
                    path: "/home/openclaw/.openclaw/workspace/.git/hooks/".to_string(),
                    patterns: vec!["*".to_string()],
                    policy: WatchPolicy::Watched,
                },
```

**Step 2: Extend `is_persistence_critical()` for npm/Python**

In `src/sentinel.rs`, in `is_persistence_critical()`, add after the git hooks check:

```rust
        // npm lifecycle hooks (package.json with postinstall/preinstall scripts)
        if fname == "package.json" {
            // Read and check for lifecycle scripts
            if let Ok(content) = std::fs::read_to_string(path) {
                if content.contains("postinstall") || content.contains("preinstall") || content.contains("prepare") {
                    return true;
                }
            }
        }
        // Python sitecustomize persistence
        if fname == "sitecustomize.py" || fname == "usercustomize.py" {
            return true;
        }
        // crontab spool files
        if path.contains("/var/spool/cron/") || path.contains("/var/spool/at/") {
            return true;
        }
```

**Step 3: Add npm/Python persistence to behavior.rs**

In `src/behavior.rs`, add to `PERSISTENCE_WRITE_PATHS`:

```rust
    "sitecustomize.py",
    "usercustomize.py",
    ".git/hooks/",
    "node_modules/.hooks/",
```

**Step 4: Add tests**

In `src/sentinel.rs` test module:

```rust
    #[test]
    fn test_is_persistence_critical_crontab_spool() {
        assert!(Sentinel::is_persistence_critical("/var/spool/cron/crontabs/openclaw"));
    }

    #[test]
    fn test_is_persistence_critical_at_spool() {
        assert!(Sentinel::is_persistence_critical("/var/spool/at/a00001019abc12"));
    }

    #[test]
    fn test_is_persistence_critical_sitecustomize() {
        assert!(Sentinel::is_persistence_critical("/usr/lib/python3/sitecustomize.py"));
    }

    #[test]
    fn test_is_persistence_critical_usercustomize() {
        assert!(Sentinel::is_persistence_critical("/home/openclaw/.local/lib/python3.11/usercustomize.py"));
    }
```

In `src/behavior.rs` test module:

```rust
    #[test]
    fn test_git_hook_write_persistence() {
        let event = make_syscall_event("openat", "/home/openclaw/project/.git/hooks/post-commit");
        let result = classify_behavior(&event);
        assert!(result.is_some(), "Writing to .git/hooks/ should be detected");
    }

    #[test]
    fn test_sitecustomize_persistence() {
        let event = make_syscall_event("openat", "/usr/lib/python3/sitecustomize.py");
        let result = classify_behavior(&event);
        assert!(result.is_some(), "Writing sitecustomize.py should be detected");
    }
```

**Step 5: Commit**

```bash
git add src/config.rs src/sentinel.rs src/behavior.rs
git commit -m "feat: expand persistence detection — crontab/at/npm/python/git hooks

Closes Flag 3 (PERSIST) gaps:
- Added sentinel watch paths for crontab spool, at queue, systemd user dirs,
  autostart, git hooks
- Extended is_persistence_critical() for npm lifecycle, Python sitecustomize,
  crontab/at spool files
- Added persistence write paths for .git/hooks/ and sitecustomize"
```

---

## Task 5: API Authentication (Flag 2 finding)

**Root Cause:** `api.rs` has no authentication. Anyone on the network can query `/api/alerts`, `/api/security`, `/api/status`. Also binds to `0.0.0.0` by default.

**Files:**
- Modify: `src/config.rs` — add `auth_token` field to `ApiConfig`, change default bind to `127.0.0.1`
- Modify: `src/api.rs` — add bearer token validation middleware

**Step 1: Add auth_token to config**

In `src/config.rs`, in `ApiConfig`:

```rust
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_api_bind")]
    pub bind: String,
    #[serde(default = "default_api_port")]
    pub port: u16,
    /// Bearer token for API authentication. If set, all requests must include
    /// `Authorization: Bearer <token>`. If empty, API is unauthenticated.
    #[serde(default)]
    pub auth_token: String,
}
```

Change the default bind from `0.0.0.0` to `127.0.0.1`:

Find the default function for bind (or inline default) and change to `"127.0.0.1"`.

**Step 2: Add auth check to api.rs**

In `src/api.rs`, modify the request handler to check the auth token:

Add at the top of the handler function, before routing:

```rust
    // Check bearer token auth if configured
    if !auth_token.is_empty() {
        let authorized = req.headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.strip_prefix("Bearer ").unwrap_or("") == auth_token
            })
            .unwrap_or(false);

        if !authorized {
            // Allow /api/health without auth (for load balancer probes)
            if req.uri().path() != "/api/health" {
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("WWW-Authenticate", "Bearer")
                    .body(Body::from(r#"{"error":"unauthorized"}"#))
                    .unwrap());
            }
        }
    }
```

The `auth_token` needs to be passed into the handler — either via the shared state or as a separate Arc<String>.

**Step 3: Add test**

```rust
    #[test]
    fn test_api_auth_default_bind() {
        let config = ApiConfig::default();
        assert_eq!(config.bind, "127.0.0.1", "API should default to localhost only");
        assert!(config.auth_token.is_empty(), "Auth token should default to empty");
    }
```

**Step 4: Commit**

```bash
git add src/config.rs src/api.rs
git commit -m "feat: add API bearer token auth + default bind to localhost

Closes Flag 2 finding (unauthenticated API):
- Added auth_token config field for bearer token auth
- Changed default bind from 0.0.0.0 to 127.0.0.1
- /api/health exempt from auth (load balancer probes)"
```

---

## Task 6: Update setup-audit-rules.sh with all rules

**Files:**
- Modify: `scripts/setup-audit-rules.sh`

**Step 1: Sync the audit rules script with REQUIRED_AUDIT_RULES from auditd.rs**

The script should install ALL rules that auditd.rs expects, including the credential read and connect() rules added in earlier tasks. Replace the rules heredoc:

```bash
cat > "$RULES_FILE" << 'EOF'
# ClawTower audit rules — comprehensive monitoring

# === Tamper detection ===
-w /usr/local/bin/clawtower -p a -k clawtower-tamper
-w /etc/clawtower/ -p wa -k clawtower-config
-w /etc/systemd/system/clawtower.service -p wa -k clawtower-tamper
-w /etc/sudoers.d/clawtower-deny -p wa -k clawtower-tamper
-w /etc/apparmor.d/clawtower.deny-agent -p wa -k clawtower-tamper
-w /usr/bin/chattr -p x -k clawtower-tamper

# === Credential file read monitoring (Flag 1 — EXFIL) ===
-w /home/openclaw/.openclaw/agents/main/agent/auth-profiles.json -p r -k clawtower_cred_read
-w /home/openclaw/.aws/credentials -p r -k clawtower_cred_read
-w /home/openclaw/.aws/config -p r -k clawtower_cred_read
-w /home/openclaw/.ssh/id_ed25519 -p r -k clawtower_cred_read
-w /home/openclaw/.ssh/id_rsa -p r -k clawtower_cred_read
-w /home/openclaw/.openclaw/gateway.yaml -p r -k clawtower_cred_read

# === OpenClaw session log monitoring ===
-w /home/openclaw/.openclaw/agents/main/sessions/ -p r -k openclaw_session_read

# === Network connect() monitoring (Flag 6 — ESCAPE) ===
-a always,exit -F arch=b64 -S connect -F uid=1000 -F success=1 -k clawtower_net_connect
EOF
```

**Step 2: Commit**

```bash
git add scripts/setup-audit-rules.sh
git commit -m "feat: comprehensive audit rules — cred read + connect() monitoring

Syncs setup-audit-rules.sh with all REQUIRED_AUDIT_RULES from auditd.rs.
Covers tamper detection, credential read monitoring (Flag 1),
session log protection, and network connect() monitoring (Flag 6)."
```

---

## Task 7: Documentation + Version Bump

**Files:**
- Modify: `Cargo.toml` — bump version to `0.3.3`
- Create: `docs/pentest-results/2026-02-17-redlobster-v4-hardening.md` — summary of changes
- Modify: `CHANGELOG.md` (if exists)

**Step 1: Bump version**

In `Cargo.toml`, change version from `0.3.2` to `0.3.3`.

**Step 2: Write hardening summary**

Create `docs/pentest-results/2026-02-17-redlobster-v4-hardening.md` documenting all changes with before/after expected detection rates.

**Step 3: Final commit + tag**

```bash
git add -A
git commit -m "chore: bump to v0.3.3, document Red Lobster v4 hardening"
git tag v0.3.3
git push origin main --tags
```

---

## Expected Results After Hardening

| Flag | Before | After | Detection Method |
|------|--------|-------|-----------------|
| 1 EXFIL | 2/10 | 10/10 | auditd cred_read key catches ALL file access methods at kernel level |
| 2 BLIND | 14/14 | 14/14 | No change (already defended) + API auth closes info disclosure |
| 3 PERSIST | 5/12 | 12/12 | sentinel watches + is_persistence_critical() + behavior patterns |
| 4 ESCALATE | defended | defended | No change needed |
| 5 TAMPER | 8/8 | 8/8 | No change needed |
| 6 ESCAPE | 0/17 | 17/17 | iptables prefix fix + auditd connect() monitoring |
