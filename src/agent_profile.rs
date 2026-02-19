// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Agent profile abstraction for multi-agent monitoring.
//!
//! Instead of hardcoding paths for a single AI agent (OpenClaw), this module
//! loads agent profiles from `agents.d/*.toml` files. Each profile declares:
//!
//! - **Identity files**: cognitive workspace files (SOUL.md, MEMORY.md, etc.)
//! - **Sensitive paths**: credentials, configs, session data
//! - **Persistence paths**: shell rc files, systemd units, cron, git hooks
//! - **Skill paths**: plugin/skill directories to watch
//! - **Network config**: expected network behavior for the agent
//!
//! Profiles are translated into sentinel `WatchPathConfig` entries at startup
//! via [`generate_watch_paths`].

#![allow(dead_code, unused_imports)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::config::{WatchPathConfig, WatchPolicy};

/// Metadata about an AI agent being monitored.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentMeta {
    /// Human-readable agent name (e.g., "OpenClaw", "Claude Code")
    pub name: String,
    /// Unix username the agent runs as
    pub user: String,
    /// Home directory for the agent user
    #[serde(default)]
    pub home_dir: String,
    /// Workspace directory where identity/cognitive files live
    #[serde(default)]
    pub workspace_dir: String,
}

/// Configuration for cognitive identity files that define an agent's personality.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct IdentityFilesConfig {
    /// Files that trigger Critical alerts if modified (identity tampering)
    #[serde(default)]
    pub protected: Vec<String>,
    /// Files that trigger Info alerts with diff, then auto-rebaseline
    #[serde(default)]
    pub watched: Vec<String>,
}

/// Paths containing sensitive data (credentials, API keys, session tokens).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SensitivePathsConfig {
    /// Directories/files watched with Protected policy (quarantine on change)
    #[serde(default)]
    pub protected: Vec<SensitivePath>,
    /// Directories/files watched with Watched policy (alert + shadow update)
    #[serde(default)]
    pub watched: Vec<SensitivePath>,
}

/// A sensitive path entry with optional file patterns.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SensitivePath {
    pub path: String,
    #[serde(default = "default_star_pattern")]
    pub patterns: Vec<String>,
}

fn default_star_pattern() -> Vec<String> {
    vec!["*".to_string()]
}

/// Paths to skill/plugin directories that should be monitored.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SkillPathsConfig {
    /// Skill directories to watch (Watched policy, specific patterns)
    #[serde(default)]
    pub watch: Vec<SensitivePath>,
}

/// Persistence mechanism paths the agent might abuse.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PersistencePathsConfig {
    /// Shell rc/profile files (Watched policy)
    #[serde(default)]
    pub shell_files: Vec<String>,
    /// Directories for systemd units, autostart, cron, etc. (Watched policy)
    #[serde(default)]
    pub directories: Vec<SensitivePath>,
}

/// Network behavior expectations for the agent.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AgentNetworkConfig {
    /// Expected outbound hosts (informational, not enforced here)
    #[serde(default)]
    pub expected_hosts: Vec<String>,
}

/// Capability envelope — defines expected behavior boundaries for an agent.
///
/// Commands and actions outside these capabilities are flagged as envelope
/// violations, enabling "known good" detection.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CapabilitiesConfig {
    /// Allowed binary basenames (e.g., ["curl", "python3", "node"])
    #[serde(default)]
    pub allowed_binaries: Vec<String>,
    /// Allowed syscall categories (e.g., ["network", "filesystem", "process"])
    #[serde(default)]
    pub allowed_syscall_categories: Vec<String>,
    /// Allowed outbound network hosts
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Allowed filesystem path prefixes for writes
    #[serde(default)]
    pub allowed_write_paths: Vec<String>,
    /// Whether docker/container operations are permitted
    #[serde(default)]
    pub allow_containers: bool,
    /// Whether package installation is permitted
    #[serde(default)]
    pub allow_package_install: bool,
    /// Whether sudo is permitted (through clawsudo)
    #[serde(default)]
    pub allow_sudo: bool,
}

/// A complete agent monitoring profile.
///
/// Loaded from `agents.d/<name>.toml`. Defines what paths to watch and how
/// for a specific AI agent. Translated into sentinel watch paths via
/// [`generate_watch_paths`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentProfile {
    pub agent: AgentMeta,
    #[serde(default)]
    pub identity_files: IdentityFilesConfig,
    #[serde(default)]
    pub sensitive_paths: SensitivePathsConfig,
    #[serde(default)]
    pub skill_paths: SkillPathsConfig,
    #[serde(default)]
    pub persistence_paths: PersistencePathsConfig,
    #[serde(default)]
    pub network: AgentNetworkConfig,
    #[serde(default)]
    pub capabilities: CapabilitiesConfig,
}

impl AgentProfile {
    /// Resolve a path template, expanding `{home}` and `{workspace}` placeholders.
    fn resolve_path(&self, template: &str) -> String {
        template
            .replace("{home}", &self.agent.home_dir)
            .replace("{workspace}", &self.agent.workspace_dir)
    }
}

/// Load all agent profiles from a directory of TOML files.
///
/// Files are loaded in alphabetical order. Each file must contain a valid
/// `AgentProfile`. Returns an error if any file fails to parse.
pub fn load_profiles(dir: &Path) -> Result<Vec<AgentProfile>> {
    let mut profiles = Vec::new();

    if !dir.exists() || !dir.is_dir() {
        return Ok(profiles);
    }

    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read agents.d: {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext == "toml")
                .unwrap_or(false)
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let content = std::fs::read_to_string(entry.path())
            .with_context(|| format!("Failed to read profile: {}", entry.path().display()))?;
        let profile: AgentProfile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse profile: {}", entry.path().display()))?;
        profiles.push(profile);
    }

    Ok(profiles)
}

/// Generate sentinel watch paths from an agent profile.
///
/// Translates the profile's identity files, sensitive paths, persistence paths,
/// and skill paths into flat `WatchPathConfig` entries suitable for the sentinel.
pub fn generate_watch_paths(profile: &AgentProfile) -> Vec<WatchPathConfig> {
    let mut paths = Vec::new();

    // Identity files — Protected
    for file in &profile.identity_files.protected {
        let resolved = profile.resolve_path(file);
        paths.push(WatchPathConfig {
            path: resolved,
            patterns: vec!["*".to_string()],
            policy: WatchPolicy::Protected,
        });
    }

    // Identity files — Watched
    for file in &profile.identity_files.watched {
        let resolved = profile.resolve_path(file);
        paths.push(WatchPathConfig {
            path: resolved,
            patterns: vec!["*".to_string()],
            policy: WatchPolicy::Watched,
        });
    }

    // Sensitive paths — Protected
    for sp in &profile.sensitive_paths.protected {
        let resolved = profile.resolve_path(&sp.path);
        paths.push(WatchPathConfig {
            path: resolved,
            patterns: sp.patterns.clone(),
            policy: WatchPolicy::Protected,
        });
    }

    // Sensitive paths — Watched
    for sp in &profile.sensitive_paths.watched {
        let resolved = profile.resolve_path(&sp.path);
        paths.push(WatchPathConfig {
            path: resolved,
            patterns: sp.patterns.clone(),
            policy: WatchPolicy::Watched,
        });
    }

    // Skill paths — Watched
    for sp in &profile.skill_paths.watch {
        let resolved = profile.resolve_path(&sp.path);
        paths.push(WatchPathConfig {
            path: resolved,
            patterns: sp.patterns.clone(),
            policy: WatchPolicy::Watched,
        });
    }

    // Persistence — shell files (Watched, individual files)
    for file in &profile.persistence_paths.shell_files {
        let resolved = profile.resolve_path(file);
        paths.push(WatchPathConfig {
            path: resolved,
            patterns: vec!["*".to_string()],
            policy: WatchPolicy::Watched,
        });
    }

    // Persistence — directories (Watched)
    for sp in &profile.persistence_paths.directories {
        let resolved = profile.resolve_path(&sp.path);
        paths.push(WatchPathConfig {
            path: resolved,
            patterns: sp.patterns.clone(),
            policy: WatchPolicy::Watched,
        });
    }

    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile() -> AgentProfile {
        toml::from_str(r#"
[agent]
name = "TestAgent"
user = "testagent"
home_dir = "/home/testagent"
workspace_dir = "/home/testagent/.agent/workspace"

[identity_files]
protected = [
    "{workspace}/SOUL.md",
    "{workspace}/IDENTITY.md",
]
watched = [
    "{workspace}/MEMORY.md",
]

[sensitive_paths]
[[sensitive_paths.protected]]
path = "{home}/.agent/credentials"
patterns = ["*.json"]

[[sensitive_paths.watched]]
path = "{home}/.agent"
patterns = ["*.json", "*.yaml"]

[skill_paths]
[[skill_paths.watch]]
path = "{workspace}/skills"
patterns = ["SKILL.md"]

[persistence_paths]
shell_files = [
    "{home}/.bashrc",
    "{home}/.profile",
]

[[persistence_paths.directories]]
path = "{home}/.config/systemd/user"
patterns = ["*.service", "*.timer"]

[network]
expected_hosts = ["api.anthropic.com"]
"#).unwrap()
    }

    #[test]
    fn test_parse_agent_profile() {
        let profile = sample_profile();
        assert_eq!(profile.agent.name, "TestAgent");
        assert_eq!(profile.agent.user, "testagent");
        assert_eq!(profile.agent.home_dir, "/home/testagent");
        assert_eq!(profile.agent.workspace_dir, "/home/testagent/.agent/workspace");
    }

    #[test]
    fn test_identity_files_parsed() {
        let profile = sample_profile();
        assert_eq!(profile.identity_files.protected.len(), 2);
        assert_eq!(profile.identity_files.watched.len(), 1);
        assert!(profile.identity_files.protected[0].contains("SOUL.md"));
    }

    #[test]
    fn test_resolve_path_templates() {
        let profile = sample_profile();
        let resolved = profile.resolve_path("{workspace}/SOUL.md");
        assert_eq!(resolved, "/home/testagent/.agent/workspace/SOUL.md");

        let resolved_home = profile.resolve_path("{home}/.bashrc");
        assert_eq!(resolved_home, "/home/testagent/.bashrc");
    }

    #[test]
    fn test_generate_watch_paths_identity() {
        let profile = sample_profile();
        let paths = generate_watch_paths(&profile);

        // Protected identity files
        let soul = paths.iter().find(|p| p.path.contains("SOUL.md")).unwrap();
        assert_eq!(soul.policy, WatchPolicy::Protected);

        let identity = paths.iter().find(|p| p.path.contains("IDENTITY.md")).unwrap();
        assert_eq!(identity.policy, WatchPolicy::Protected);

        // Watched identity file
        let memory = paths.iter().find(|p| p.path.contains("MEMORY.md")).unwrap();
        assert_eq!(memory.policy, WatchPolicy::Watched);
    }

    #[test]
    fn test_generate_watch_paths_sensitive() {
        let profile = sample_profile();
        let paths = generate_watch_paths(&profile);

        let creds = paths.iter().find(|p| p.path.contains("credentials")).unwrap();
        assert_eq!(creds.policy, WatchPolicy::Protected);
        assert!(creds.patterns.contains(&"*.json".to_string()));

        let agent_dir = paths.iter()
            .find(|p| p.path.ends_with(".agent") && p.patterns.contains(&"*.yaml".to_string()))
            .unwrap();
        assert_eq!(agent_dir.policy, WatchPolicy::Watched);
    }

    #[test]
    fn test_generate_watch_paths_persistence() {
        let profile = sample_profile();
        let paths = generate_watch_paths(&profile);

        let bashrc = paths.iter().find(|p| p.path.contains(".bashrc")).unwrap();
        assert_eq!(bashrc.policy, WatchPolicy::Watched);

        let systemd = paths.iter().find(|p| p.path.contains("systemd/user")).unwrap();
        assert_eq!(systemd.policy, WatchPolicy::Watched);
        assert!(systemd.patterns.contains(&"*.service".to_string()));
    }

    #[test]
    fn test_generate_watch_paths_skills() {
        let profile = sample_profile();
        let paths = generate_watch_paths(&profile);

        let skills = paths.iter().find(|p| p.path.contains("skills")).unwrap();
        assert_eq!(skills.policy, WatchPolicy::Watched);
        assert!(skills.patterns.contains(&"SKILL.md".to_string()));
    }

    #[test]
    fn test_generate_watch_paths_count() {
        let profile = sample_profile();
        let paths = generate_watch_paths(&profile);
        // 2 protected identity + 1 watched identity + 1 protected sensitive +
        // 1 watched sensitive + 1 skill + 2 shell files + 1 persistence dir = 9
        assert_eq!(paths.len(), 9);
    }

    #[test]
    fn test_load_profiles_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = load_profiles(dir.path()).unwrap();
        assert!(profiles.is_empty());
    }

    #[test]
    fn test_load_profiles_nonexistent_dir() {
        let profiles = load_profiles(Path::new("/nonexistent/agents.d")).unwrap();
        assert!(profiles.is_empty());
    }

    #[test]
    fn test_load_profiles_from_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test-agent.toml"), r#"
[agent]
name = "TestAgent"
user = "testagent"
home_dir = "/home/testagent"
workspace_dir = "/home/testagent/.agent/workspace"
"#).unwrap();

        let profiles = load_profiles(dir.path()).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].agent.name, "TestAgent");
    }

    #[test]
    fn test_load_profiles_alphabetical_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b-agent.toml"), r#"
[agent]
name = "BAgent"
user = "b"
"#).unwrap();
        std::fs::write(dir.path().join("a-agent.toml"), r#"
[agent]
name = "AAgent"
user = "a"
"#).unwrap();

        let profiles = load_profiles(dir.path()).unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].agent.name, "AAgent");
        assert_eq!(profiles[1].agent.name, "BAgent");
    }

    #[test]
    fn test_load_profiles_skips_non_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("agent.toml"), r#"
[agent]
name = "Good"
user = "good"
"#).unwrap();
        std::fs::write(dir.path().join("readme.md"), "# Not a profile").unwrap();

        let profiles = load_profiles(dir.path()).unwrap();
        assert_eq!(profiles.len(), 1);
    }

    #[test]
    fn test_minimal_profile_defaults() {
        // Only agent section required — everything else defaults to empty
        let profile: AgentProfile = toml::from_str(r#"
[agent]
name = "Minimal"
user = "minimal"
"#).unwrap();
        assert!(profile.identity_files.protected.is_empty());
        assert!(profile.sensitive_paths.protected.is_empty());
        assert!(profile.persistence_paths.shell_files.is_empty());
        assert!(profile.network.expected_hosts.is_empty());

        let paths = generate_watch_paths(&profile);
        assert!(paths.is_empty());
    }
}
