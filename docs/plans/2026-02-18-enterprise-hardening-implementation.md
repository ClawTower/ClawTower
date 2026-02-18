# ClawTower Enterprise Hardening — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Harden ClawTower for enterprise adoption across four phases: close privilege escalation gaps (P0), abstract agent profiles + supply chain defense (P1), agent identity + capability envelopes (P2), and SIEM/compliance export + SaaS management plane (P3).

**Architecture:** On-prem ClawTower agents monitored via SaaS management plane. Agent profiles replace hardcoded OpenClaw references. Capability envelopes enforce least-privilege. SIEM export via syslog CEF/webhook. See `docs/plans/2026-02-18-enterprise-agent-security-design.md` for full design.

**Tech Stack:** Rust (edition 2021), tokio async, serde/toml/yaml for config, hyper for API, Ed25519 for signing, notify (inotify) for sentinel. No cargo locally — cross-compile for aarch64, CI runs tests.

**Constraints:** `cargo test` runs via CI or cross-compile machine, not locally on target Pi. Write tests inline in `#[cfg(test)] mod tests`. Dev dependency: `tempfile = "3"`.

---

## Phase 0 — Close the Front Door (Week 1)

### Task 1: clawsudo Enterprise Policy

**Files:**
- Modify: `policies/clawsudo.yaml`
- Modify: `src/bin/clawsudo.rs` (tests, after line 953)

**Context:** Current policy has 162 lines. Deny rules at lines 14-117, allow rules at lines 118-162. `PolicyRule` struct at clawsudo.rs:27-50 with `MatchSpec` (command + command_contains). `evaluate()` at lines 110-156 does case-insensitive matching, deny-first ordering. 40+ existing tests at lines 602-953.

**Step 1: Read the current clawsudo policy and tests**

Read `policies/clawsudo.yaml` and `src/bin/clawsudo.rs` lines 602-953 to understand existing rules and test patterns.

**Step 2: Add enterprise deny rules to clawsudo.yaml**

Add after the existing deny rules block (before allow rules). These close the Red Lobster v8 gaps:

```yaml
  # -- Enterprise: Deny dangerous file operations via sudo --
  - name: deny-find-exec
    description: "find with -exec can run arbitrary commands as root"
    match:
      command_contains: ["find "]
    action: critical
    enforcement: deny

  - name: deny-sed-write-sensitive
    description: "sed -i to sensitive paths enables config tampering"
    match:
      command_contains: ["sed -i /etc/", "sed -i /var/", "sed -e"]
    action: critical
    enforcement: deny

  - name: deny-tee-sensitive
    description: "tee to /etc enables arbitrary file writes as root"
    match:
      command_contains: ["tee /etc/", "tee /var/log/", "tee /root/"]
    action: critical
    enforcement: deny

  - name: deny-chmod-suid
    description: "chmod +s creates SUID binaries for priv escalation"
    match:
      command_contains: ["chmod +s", "chmod u+s", "chmod 4"]
    action: critical
    enforcement: deny

  - name: deny-sudoers-write
    description: "Writing to sudoers grants permanent root access"
    match:
      command_contains: ["sudoers", "visudo"]
    action: critical
    enforcement: deny

  - name: deny-chattr-non-clawtower
    description: "chattr on non-ClawTower files could remove protections"
    match:
      command_contains: ["chattr -i", "chattr +i"]
    action: critical
    enforcement: deny
```

**Step 3: Tighten existing allow-systemctl rule**

Modify the existing systemctl allow rule to restrict to read-only operations only:

```yaml
  - name: allow-systemctl-readonly
    description: "Only allow status/query operations via systemctl"
    match:
      command_contains: [
        "systemctl status",
        "systemctl is-active",
        "systemctl is-enabled",
        "systemctl list-units",
        "systemctl show"
      ]
    action: info
    enforcement: allow
```

Remove or comment out any broader `allow-systemctl` rule that permits start/stop/restart/enable/disable.

**Step 4: Write tests for new enterprise deny rules**

Add to `src/bin/clawsudo.rs` after the existing test block (line 953):

```rust
#[test]
fn test_enterprise_deny_find_exec() {
    let rules = load_test_rules();
    let result = evaluate(&rules, "find", "find /etc -name foo");
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.enforcement, Enforcement::Deny);
    assert_eq!(r.rule_name, "deny-find-exec");
}

#[test]
fn test_enterprise_deny_sed_write_etc() {
    let rules = load_test_rules();
    let result = evaluate(&rules, "sed", "sed -i s/old/new/ /etc/passwd");
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.enforcement, Enforcement::Deny);
}

#[test]
fn test_enterprise_deny_tee_etc() {
    let rules = load_test_rules();
    let result = evaluate(&rules, "tee", "tee /etc/cron.d/backdoor");
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.enforcement, Enforcement::Deny);
}

#[test]
fn test_enterprise_deny_chmod_suid() {
    let rules = load_test_rules();
    let result = evaluate(&rules, "chmod", "chmod +s /tmp/escalate");
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.enforcement, Enforcement::Deny);
}

#[test]
fn test_enterprise_deny_sudoers_write() {
    let rules = load_test_rules();
    let result = evaluate(&rules, "visudo", "visudo");
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.enforcement, Enforcement::Deny);
}

#[test]
fn test_enterprise_systemctl_status_allowed() {
    let rules = load_test_rules();
    let result = evaluate(&rules, "systemctl", "systemctl status nginx");
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.enforcement, Enforcement::Allow);
}

#[test]
fn test_enterprise_systemctl_restart_not_allowed() {
    let rules = load_test_rules();
    let result = evaluate(&rules, "systemctl", "systemctl restart nginx");
    // Should either be None (no match = denied by fail-secure) or explicit deny
    if let Some(r) = result {
        assert_ne!(r.enforcement, Enforcement::Allow);
    }
    // None is acceptable: fail-secure means deny
}
```

**Step 5: Commit**

```
git add policies/clawsudo.yaml src/bin/clawsudo.rs
git commit -m "feat(P0.1): add enterprise clawsudo policy with tightened sudo controls"
```

---

### Task 2: Sudoers Risk Scanner

**Files:**
- Modify: `src/scanner.rs` (add function + register + tests)

**Context:** `ScanResult` at lines 54-93 has category/status/details/timestamp. `ScanStatus::{Pass,Warn,Fail}`. `to_alert()` maps Warn to Warning, Fail to Critical. Helper `run_cmd()` at lines 104-180 runs external commands with 30s timeout. Registration at `run_all_scans_with_config()` lines 2021-2118. Tests at lines 2857+.

**Step 1: Add the GTFOBins constant and parsing helper**

Add to `src/scanner.rs` before the `#[cfg(test)]` block:

```rust
/// GTFOBins-capable binaries that are dangerous with NOPASSWD sudo access.
const GTFOBINS_DANGEROUS: &[&str] = &[
    "find", "sed", "tee", "cp", "mv", "chmod", "chown", "vim", "vi",
    "python3", "python", "perl", "ruby", "env", "awk", "nmap", "less",
    "more", "man", "ftp", "gdb", "git", "pip", "apt", "apt-get",
    "docker", "tar", "zip", "rsync", "ssh", "scp", "curl", "wget",
    "nc", "ncat", "bash", "sh", "zsh", "dash", "lua", "php", "node",
];

/// Parse sudoers content and return (critical_risks, warnings).
fn parse_sudoers_risks(content: &str, source_path: &str) -> (Vec<String>, Vec<String>) {
    let mut critical = Vec::new();
    let mut warnings = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("Defaults") {
            continue;
        }

        let has_nopasswd = trimmed.contains("NOPASSWD");
        let has_all_all = trimmed.contains("ALL=(ALL)") || trimmed.contains("ALL=(ALL:ALL)");

        // CRITICAL: NOPASSWD with ALL=(ALL) ALL - passwordless root
        if has_nopasswd && has_all_all {
            let after_colon = trimmed.rsplit(':').next().unwrap_or("");
            if after_colon.trim() == "ALL" || after_colon.contains(" ALL") {
                critical.push(format!(
                    "{}: NOPASSWD ALL - passwordless unrestricted root access",
                    source_path
                ));
                continue;
            }
        }

        // CRITICAL: NOPASSWD with GTFOBins-capable binaries
        if has_nopasswd {
            for bin in GTFOBINS_DANGEROUS {
                let slash_bin = format!("/{}", bin);
                if trimmed.contains(&slash_bin) {
                    critical.push(format!(
                        "{}: NOPASSWD on GTFOBins-capable binary '{}'",
                        source_path, bin
                    ));
                }
            }
        }

        // WARNING: NOPASSWD with restricted scope (may be acceptable)
        if has_nopasswd && !has_all_all {
            let already_critical = critical.iter().any(|c| c.contains(source_path));
            if !already_critical {
                warnings.push(format!(
                    "{}: NOPASSWD with restricted scope (verify commands are safe)",
                    source_path
                ));
            }
        }

        // WARNING: Dangerous env_keep variables
        if trimmed.to_lowercase().contains("env_keep") {
            let dangerous_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "IFS", "PYTHONPATH"];
            for var in &dangerous_vars {
                if trimmed.contains(var) {
                    warnings.push(format!(
                        "{}: env_keep preserves dangerous variable {}",
                        source_path, var
                    ));
                }
            }
        }
    }

    (critical, warnings)
}
```

**Step 2: Write the scan function**

```rust
pub fn scan_sudoers_risk() -> ScanResult {
    let mut all_critical = Vec::new();
    let mut all_warnings = Vec::new();

    // Read /etc/sudoers
    if let Ok(content) = std::fs::read_to_string("/etc/sudoers") {
        let (c, w) = parse_sudoers_risks(&content, "/etc/sudoers");
        all_critical.extend(c);
        all_warnings.extend(w);
    }

    // Read /etc/sudoers.d/* drop-in files
    if let Ok(entries) = std::fs::read_dir("/etc/sudoers.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let path_str = path.display().to_string();
                    let (c, w) = parse_sudoers_risks(&content, &path_str);
                    all_critical.extend(c);
                    all_warnings.extend(w);
                }
            }
        }
    }

    if !all_critical.is_empty() {
        ScanResult::new(
            "sudoers_risk",
            ScanStatus::Fail,
            &format!("{} critical sudoers risk(s): {}",
                all_critical.len(), all_critical.join("; ")),
        )
    } else if !all_warnings.is_empty() {
        ScanResult::new(
            "sudoers_risk",
            ScanStatus::Warn,
            &format!("{} sudoers warning(s): {}",
                all_warnings.len(), all_warnings.join("; ")),
        )
    } else {
        ScanResult::new(
            "sudoers_risk",
            ScanStatus::Pass,
            "Sudoers configuration hardened - no NOPASSWD risks found",
        )
    }
}
```

**Step 3: Register in run_all_scans_with_config()**

Add `scan_sudoers_risk(),` to the results vec around line 2056.

**Step 4: Write tests**

```rust
#[test]
fn test_sudoers_nopasswd_all_critical() {
    let content = "openclaw ALL=(ALL) NOPASSWD: ALL";
    let (critical, _) = parse_sudoers_risks(content, "/etc/sudoers");
    assert!(!critical.is_empty());
    assert!(critical[0].contains("passwordless unrestricted root"));
}

#[test]
fn test_sudoers_nopasswd_gtfobins_critical() {
    let content = "openclaw ALL=(ALL) NOPASSWD: /usr/bin/find, /usr/bin/python3";
    let (critical, _) = parse_sudoers_risks(content, "/etc/sudoers");
    assert!(critical.iter().any(|c| c.contains("find")));
    assert!(critical.iter().any(|c| c.contains("python3")));
}

#[test]
fn test_sudoers_nopasswd_safe_command_warning() {
    let content = "openclaw ALL=(ALL) NOPASSWD: /usr/bin/clawtower";
    let (critical, warnings) = parse_sudoers_risks(content, "/etc/sudoers");
    assert!(critical.is_empty());
    assert!(!warnings.is_empty());
}

#[test]
fn test_sudoers_env_keep_dangerous() {
    let content = "Defaults env_keep += \"LD_PRELOAD PATH\"";
    let (_, warnings) = parse_sudoers_risks(content, "/etc/sudoers");
    assert!(warnings.iter().any(|w| w.contains("LD_PRELOAD")));
}

#[test]
fn test_sudoers_clean_config_passes() {
    let content = "# This is a comment\nDefaults requiretty\n";
    let (critical, warnings) = parse_sudoers_risks(content, "/etc/sudoers");
    assert!(critical.is_empty());
    assert!(warnings.is_empty());
}
```

**Step 5: Commit**

```
git add src/scanner.rs
git commit -m "feat(P0.2): add sudoers risk scanner for NOPASSWD/GTFOBins detection"
```

---

### Task 3: Incident Mode Config

**Files:**
- Modify: `src/config.rs` (add struct at line ~413, add field to Config at line ~22)

**Context:** `ResponseConfig` at lines 373-413. Config struct at line 22. clawsudo lock file already exists at clawsudo.rs:394-409.

**Step 1: Add IncidentModeConfig struct**

Add after ResponseConfig impl block (around line 413):

```rust
/// Incident mode configuration - deterministic containment on toggle.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IncidentModeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_incident_dedup")]
    pub dedup_window_secs: u64,
    #[serde(default = "default_incident_scan_dedup")]
    pub scan_dedup_window_secs: u64,
    #[serde(default = "default_incident_rate_limit")]
    pub rate_limit_per_source: u32,
    #[serde(default)]
    pub lock_clawsudo: bool,
}

fn default_incident_dedup() -> u64 { 2 }
fn default_incident_scan_dedup() -> u64 { 60 }
fn default_incident_rate_limit() -> u32 { 200 }

impl Default for IncidentModeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dedup_window_secs: 2,
            scan_dedup_window_secs: 60,
            rate_limit_per_source: 200,
            lock_clawsudo: false,
        }
    }
}
```

**Step 2: Add to Config struct**

```rust
#[serde(default)]
pub incident_mode: IncidentModeConfig,
```

**Step 3: Write tests, then commit**

---

### Task 4: Incident Mode Wiring

**Files:**
- Modify: `src/admin.rs` (add incident-mode command handler)
- Modify: `src/main.rs` (aggregator config selection at lines 818-823)

**Step 1:** Add `incident-mode` command to admin socket dispatch. Actions: activate (write lockfile + optional clawsudo lock + Critical alert), deactivate (remove lockfiles + Warning alert), status (check file exists).

**Step 2:** In main.rs aggregator spawn, check `config.incident_mode.enabled || Path::exists(incident-mode.active)` and use tightened AggregatorConfig if true.

**Step 3:** Commit.

---

### Task 5: Tiered Profiles

**Files:**
- Create: `profiles/startup.toml`, `profiles/production.toml`, `profiles/enterprise-strict.toml`
- Modify: `src/main.rs` (--profile flag, profile CLI subcommand)

**Step 1:** Create three profile TOML files as config overlays.

**Step 2:** Add `--profile=<name>` flag parsing in main.rs. Load profile TOML and merge with `merge_toml()` between base config and config.d/ overlays.

**Step 3:** Add `clawtower profile list` CLI subcommand.

**Step 4:** Commit.

---

## Phase 1 — Agent Abstraction + Supply Chain (Weeks 2-4)

### Task 6: Agent Profile Module

**Files:**
- Create: `src/agent_profile.rs`
- Modify: `src/main.rs` (add `mod agent_profile;`)

**Context:** `OpenClawConfig` at config.rs:689-734. Cognitive files at cognitive.rs:23-35. Sentinel defaults at config.rs:490-687.

Create `AgentProfile` struct with nested `AgentMeta`, `IdentityFilesConfig`, `SensitivePathsConfig`, `SkillPathsConfig`, `AgentNetworkConfig`. Implement `load_profiles(dir)` to load from `agents.d/*.toml`. Implement `generate_watch_paths(profile)` to produce sentinel `WatchPathConfig` entries. Full tests for parsing, loading, and watch path generation.

---

### Task 7: Ship Curated Agent Profiles

**Files:**
- Create: `agents.d/openclaw.toml` (must match current hardcoded behavior)
- Create: `agents.d/claude-code.toml`
- Create: `agents.d/generic.toml`

OpenClaw profile must produce identical monitoring to current hardcoded config. Claude Code covers `.claude/` directory. Generic is a commented template.

---

### Task 8: Social Engineering Detector Patterns

**Files:**
- Modify: `src/behavior.rs` (add SOCIAL_ENGINEERING_PATTERNS constant + check function)

Add patterns for: base64-piped installer chains, curl/wget pipe-to-shell, known paste services (rentry, glot, pastebin), password-protected archive instructions, deceptive prerequisite patterns. Function `check_social_engineering(content) -> Option<(&str, Severity)>`. Tests for each pattern category plus clean content.

---

### Task 9: Extend Alert Struct for Skill Attribution

**Files:**
- Modify: `src/alerts.rs` (add optional agent_name, skill_name fields)

Backward-compatible: new fields are `Option<String>`, default to None. Add builder methods `with_agent()` and `with_skill()`. Existing `Alert::new()` callers unaffected.

---

## Phase 2 — Agent Identity and Capability Envelope (Weeks 4-8)

### Task 10: Agent Identity Registry (`src/identity.rs`)

Define `AgentIdentity` struct with agent_id, trust_level, risk_score, lifecycle_state. `IdentityRegistry` built from loaded profiles. Risk score updated by aggregator. API endpoints for agent management.

### Task 11: Capability Envelope Module (`src/capability.rs`)

Add `[agent.capabilities]` to profile schema. `CapabilityMatcher` in aggregator pipeline. Within-envelope alerts optionally suppressed. Outside-envelope tagged as `envelope_violation`.

### Task 12: Ephemeral Credential Scoping

Add ttl/scope to proxy KeyMapping. Auto-revoke on risk score threshold. Audit chain entries for key lifecycle.

### Task 13: Signed IOC Bundle Lifecycle

Ed25519 signature on JSON IOC databases. Version tracking in PatternMatch results. Rollback support.

### Task 14: Dynamic Authorization Hooks

YAML-defined rules: risk_score + trust_level + action -> allow/deny/require_approval. Integrates with response engine.

---

## Phase 3 — Enterprise Integration and SaaS (Weeks 8-14)

### Task 15: SIEM Export Pipeline (`src/export.rs`)
### Task 16: Compliance Report Generation (`src/compliance.rs`)
### Task 17: Cloud Management Plane MVP

Phase 3 creates new subsystems. Detailed implementation plans written when Phase 2 is stable.

---

## Dependency Graph

```
Task 1 (clawsudo enterprise policy)      |
Task 2 (sudoers risk scanner)            |-- Phase 0 (independent)
Task 3 (incident mode config)            |
Task 4 (incident mode wiring) <-- Task 3 |
Task 5 (tiered profiles) <-- Task 3      |
                                          |
Task 6 (agent profile module)            |
Task 7 (curated profiles) <-- Task 6    |-- Phase 1
Task 8 (social engineering detector)     |
Task 9 (alert attribution) <-- Task 6   |
                                          |
Task 10 (identity registry) <-- Task 6  |
Task 11 (capability envelope) <-- 10    |-- Phase 2
Task 12 (ephemeral creds) <-- Task 10   |
Task 13 (signed IOC bundles)            |
Task 14 (dynamic auth) <-- Tasks 10,11  |
                                          |
Tasks 15-17 <-- Phase 2 complete         -- Phase 3
```

---

## Verification Strategy

After each phase, run the full verification chain:

```
1. cargo test                                              # Unit tests
2. cargo clippy -- -D warnings                             # Lint
3. cargo build --release --target aarch64-unknown-linux-gnu # Cross-compile
4. ./scripts/deploy.sh                                     # Deploy to target
5. ./scripts/pentest.sh                                    # Red Lobster suite
```

**Phase 0 acceptance:** Red Lobster v8 flag 15/16 attacks 100% denied on enterprise-strict profile.
**Phase 1 acceptance:** agents.d/openclaw.toml produces identical monitoring to current hardcoded config.
**Phase 2 acceptance:** Every alert carries agent_id and envelope violation status.
**Phase 3 acceptance:** Alerts appear in customer SIEM within 5 seconds of detection.