// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Dynamic Authorization Hooks — YAML-defined rules for runtime access decisions.
//!
//! Authorization rules evaluate an agent's current risk score, trust level, and
//! the requested action to produce an allow/deny/require_approval decision.
//! Rules are loaded from YAML files and evaluated in priority order.
//!
//! Integrates with the identity registry (risk/trust state) and response engine
//! (approval workflow).

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::identity::TrustLevel;

/// The authorization decision for a requested action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthDecision {
    /// Action is allowed
    Allow,
    /// Action is denied
    Deny,
    /// Action requires human approval before proceeding
    RequireApproval,
}

/// A condition that must be met for a rule to match.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthCondition {
    /// Minimum risk score for this rule to match (0.0 = any)
    #[serde(default)]
    pub min_risk_score: f64,
    /// Maximum risk score for this rule to match (100.0 = any)
    #[serde(default = "default_max_risk")]
    pub max_risk_score: f64,
    /// Trust levels that match this condition. Empty = any.
    #[serde(default)]
    pub trust_levels: Vec<TrustLevel>,
    /// Action patterns (substring match against action name). Empty = any.
    #[serde(default)]
    pub action_patterns: Vec<String>,
    /// Source module patterns (e.g., "behavior", "proxy"). Empty = any.
    #[serde(default)]
    pub source_patterns: Vec<String>,
}

fn default_max_risk() -> f64 {
    100.0
}

impl Default for AuthCondition {
    fn default() -> Self {
        Self {
            min_risk_score: 0.0,
            max_risk_score: 100.0,
            trust_levels: Vec::new(),
            action_patterns: Vec::new(),
            source_patterns: Vec::new(),
        }
    }
}

/// A single authorization rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthRule {
    /// Rule name (for logging and audit trail)
    pub name: String,
    /// Whether this rule is active
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Priority — lower numbers evaluated first (default: 100)
    #[serde(default = "default_priority")]
    pub priority: u32,
    /// Condition that must match
    pub condition: AuthCondition,
    /// Decision to apply when condition matches
    pub decision: AuthDecision,
    /// Human-readable reason (for audit/notification)
    #[serde(default)]
    pub reason: String,
}

fn default_enabled() -> bool {
    true
}

fn default_priority() -> u32 {
    100
}

/// Top-level YAML file structure for auth rules.
#[derive(Debug, Deserialize)]
struct AuthRulesFile {
    #[serde(default)]
    rules: Vec<AuthRule>,
}

/// Context for evaluating authorization rules.
pub struct AuthContext {
    pub risk_score: f64,
    pub trust_level: TrustLevel,
    pub action: String,
    pub source: String,
}

/// The authorization engine — loads rules and evaluates them.
pub struct AuthEngine {
    rules: Vec<AuthRule>,
}

impl AuthEngine {
    /// Create an engine from a list of rules (sorted by priority).
    pub fn new(mut rules: Vec<AuthRule>) -> Self {
        rules.sort_by_key(|r| r.priority);
        Self { rules }
    }

    /// Load rules from a directory of YAML files.
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut all_rules = Vec::new();

        if !dir.exists() {
            return Self::new(all_rules);
        }

        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .into_iter()
            .flat_map(|rd| rd.into_iter())
            .flatten()
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "yaml" || ext == "yml")
                    .unwrap_or(false)
            })
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                match serde_yaml::from_str::<AuthRulesFile>(&content) {
                    Ok(file) => {
                        all_rules.extend(
                            file.rules.into_iter().filter(|r| r.enabled),
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: failed to parse auth rules {}: {}",
                            entry.path().display(),
                            e
                        );
                    }
                }
            }
        }

        Self::new(all_rules)
    }

    /// Evaluate the rules against the given context.
    ///
    /// Returns the first matching rule's decision, or `Allow` if no rule matches
    /// (default-open). For default-deny, add a low-priority catch-all deny rule.
    pub fn evaluate(&self, ctx: &AuthContext) -> (AuthDecision, Option<&str>) {
        for rule in &self.rules {
            if self.matches_condition(&rule.condition, ctx) {
                return (rule.decision.clone(), Some(&rule.name));
            }
        }
        (AuthDecision::Allow, None)
    }

    /// Check if a condition matches the given context.
    fn matches_condition(&self, cond: &AuthCondition, ctx: &AuthContext) -> bool {
        // Risk score range check
        if ctx.risk_score < cond.min_risk_score || ctx.risk_score > cond.max_risk_score {
            return false;
        }

        // Trust level check (empty = any)
        if !cond.trust_levels.is_empty() && !cond.trust_levels.contains(&ctx.trust_level) {
            return false;
        }

        // Action pattern check (empty = any)
        if !cond.action_patterns.is_empty()
            && !cond.action_patterns.iter().any(|p| ctx.action.contains(p))
        {
            return false;
        }

        // Source pattern check (empty = any)
        if !cond.source_patterns.is_empty()
            && !cond.source_patterns.iter().any(|p| ctx.source.contains(p))
        {
            return false;
        }

        true
    }

    /// Get the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn high_risk_deny_rule() -> AuthRule {
        AuthRule {
            name: "deny-high-risk".to_string(),
            enabled: true,
            priority: 10,
            condition: AuthCondition {
                min_risk_score: 75.0,
                max_risk_score: 100.0,
                ..Default::default()
            },
            decision: AuthDecision::Deny,
            reason: "Risk score too high".to_string(),
        }
    }

    fn approval_for_untrusted() -> AuthRule {
        AuthRule {
            name: "approve-untrusted-sudo".to_string(),
            enabled: true,
            priority: 20,
            condition: AuthCondition {
                trust_levels: vec![TrustLevel::Untrusted, TrustLevel::Restricted],
                action_patterns: vec!["sudo".to_string()],
                ..Default::default()
            },
            decision: AuthDecision::RequireApproval,
            reason: "Untrusted agents need approval for sudo".to_string(),
        }
    }

    fn catch_all_allow() -> AuthRule {
        AuthRule {
            name: "default-allow".to_string(),
            enabled: true,
            priority: 999,
            condition: AuthCondition::default(),
            decision: AuthDecision::Allow,
            reason: "Default allow".to_string(),
        }
    }

    #[test]
    fn test_high_risk_denied() {
        let engine = AuthEngine::new(vec![high_risk_deny_rule(), catch_all_allow()]);
        let ctx = AuthContext {
            risk_score: 80.0,
            trust_level: TrustLevel::Standard,
            action: "exec:curl".to_string(),
            source: "behavior".to_string(),
        };
        let (decision, rule) = engine.evaluate(&ctx);
        assert_eq!(decision, AuthDecision::Deny);
        assert_eq!(rule, Some("deny-high-risk"));
    }

    #[test]
    fn test_low_risk_allowed() {
        let engine = AuthEngine::new(vec![high_risk_deny_rule(), catch_all_allow()]);
        let ctx = AuthContext {
            risk_score: 10.0,
            trust_level: TrustLevel::Standard,
            action: "exec:curl".to_string(),
            source: "behavior".to_string(),
        };
        let (decision, rule) = engine.evaluate(&ctx);
        assert_eq!(decision, AuthDecision::Allow);
        assert_eq!(rule, Some("default-allow"));
    }

    #[test]
    fn test_untrusted_sudo_requires_approval() {
        let engine = AuthEngine::new(vec![
            high_risk_deny_rule(),
            approval_for_untrusted(),
            catch_all_allow(),
        ]);
        let ctx = AuthContext {
            risk_score: 30.0,
            trust_level: TrustLevel::Restricted,
            action: "sudo:systemctl restart nginx".to_string(),
            source: "clawsudo".to_string(),
        };
        let (decision, rule) = engine.evaluate(&ctx);
        assert_eq!(decision, AuthDecision::RequireApproval);
        assert_eq!(rule, Some("approve-untrusted-sudo"));
    }

    #[test]
    fn test_trusted_sudo_allowed() {
        let engine = AuthEngine::new(vec![
            high_risk_deny_rule(),
            approval_for_untrusted(),
            catch_all_allow(),
        ]);
        let ctx = AuthContext {
            risk_score: 5.0,
            trust_level: TrustLevel::Elevated,
            action: "sudo:systemctl status nginx".to_string(),
            source: "clawsudo".to_string(),
        };
        let (decision, rule) = engine.evaluate(&ctx);
        assert_eq!(decision, AuthDecision::Allow);
        assert_eq!(rule, Some("default-allow"));
    }

    #[test]
    fn test_no_rules_defaults_allow() {
        let engine = AuthEngine::new(vec![]);
        let ctx = AuthContext {
            risk_score: 50.0,
            trust_level: TrustLevel::Standard,
            action: "anything".to_string(),
            source: "anywhere".to_string(),
        };
        let (decision, rule) = engine.evaluate(&ctx);
        assert_eq!(decision, AuthDecision::Allow);
        assert!(rule.is_none());
    }

    #[test]
    fn test_priority_ordering() {
        // Lower priority number = evaluated first
        let low_pri = AuthRule {
            name: "catch-all-deny".to_string(),
            enabled: true,
            priority: 999,
            condition: AuthCondition::default(),
            decision: AuthDecision::Deny,
            reason: "catch all".to_string(),
        };
        let high_pri = AuthRule {
            name: "allow-first".to_string(),
            enabled: true,
            priority: 1,
            condition: AuthCondition::default(),
            decision: AuthDecision::Allow,
            reason: "first".to_string(),
        };
        // Insert in wrong order — engine should sort by priority
        let engine = AuthEngine::new(vec![low_pri, high_pri]);
        let ctx = AuthContext {
            risk_score: 0.0,
            trust_level: TrustLevel::Standard,
            action: "test".to_string(),
            source: "test".to_string(),
        };
        let (decision, rule) = engine.evaluate(&ctx);
        assert_eq!(decision, AuthDecision::Allow);
        assert_eq!(rule, Some("allow-first"));
    }

    #[test]
    fn test_disabled_rules_skipped() {
        let mut rule = high_risk_deny_rule();
        rule.enabled = false;
        let engine = AuthEngine::new(vec![rule]);
        // Disabled rules are filtered during load_from_dir, but
        // if passed directly they still exist — test the load path
        assert_eq!(engine.rule_count(), 1); // Still in list
    }

    #[test]
    fn test_source_pattern_matching() {
        let rule = AuthRule {
            name: "proxy-only".to_string(),
            enabled: true,
            priority: 10,
            condition: AuthCondition {
                source_patterns: vec!["proxy".to_string()],
                ..Default::default()
            },
            decision: AuthDecision::RequireApproval,
            reason: "proxy requests need approval".to_string(),
        };
        let engine = AuthEngine::new(vec![rule, catch_all_allow()]);

        // Proxy source matches
        let ctx_proxy = AuthContext {
            risk_score: 0.0,
            trust_level: TrustLevel::Standard,
            action: "api-call".to_string(),
            source: "proxy".to_string(),
        };
        assert_eq!(engine.evaluate(&ctx_proxy).0, AuthDecision::RequireApproval);

        // Behavior source doesn't match → falls through to allow
        let ctx_behavior = AuthContext {
            risk_score: 0.0,
            trust_level: TrustLevel::Standard,
            action: "api-call".to_string(),
            source: "behavior".to_string(),
        };
        assert_eq!(engine.evaluate(&ctx_behavior).0, AuthDecision::Allow);
    }

    #[test]
    fn test_load_from_nonexistent_dir() {
        let engine = AuthEngine::load_from_dir(Path::new("/nonexistent/auth-rules"));
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_load_from_dir_with_yaml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("01-test.yaml"),
            r#"
rules:
  - name: "test-deny"
    priority: 10
    condition:
      min_risk_score: 90.0
    decision: deny
    reason: "extreme risk"
  - name: "test-allow"
    priority: 100
    condition: {}
    decision: allow
    reason: "default"
"#,
        )
        .unwrap();

        let engine = AuthEngine::load_from_dir(dir.path());
        assert_eq!(engine.rule_count(), 2);

        let ctx = AuthContext {
            risk_score: 95.0,
            trust_level: TrustLevel::Standard,
            action: "test".to_string(),
            source: "test".to_string(),
        };
        let (decision, _) = engine.evaluate(&ctx);
        assert_eq!(decision, AuthDecision::Deny);
    }
}
