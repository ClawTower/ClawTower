// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

use std::collections::HashMap;

/// Source-agnostic event payload for detector evaluation.
///
/// Phase 1 note: this is scaffolding and intentionally minimal.
/// Existing engines can be adapted into this shape incrementally.
#[derive(Debug, Clone)]
pub struct DetectionEvent {
    pub source: String,
    pub event_type: String,
    pub fields: HashMap<String, String>,
    pub raw: Option<String>,
}

/// Suggested alert returned by detectors before aggregation/fanout.
///
/// Runtime must preserve the invariant that all emitted alerts still flow
/// through the central aggregator path.
#[derive(Debug, Clone)]
pub struct AlertProposal {
    pub rule_id: String,
    pub source: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub tags: Vec<String>,
}

/// Common detector interface for behavior/policy/vendor rule engines.
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str;

    /// Evaluate a normalized event and return zero or more alert proposals.
    fn evaluate(&self, event: &DetectionEvent) -> Vec<AlertProposal>;

    /// Optional quick health signal for observability/debug surfaces.
    fn health(&self) -> DetectorHealth {
        DetectorHealth::Healthy
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorHealth {
    Healthy,
    Degraded,
    Failed,
}

/// Rule provider abstraction to support externalized rule bundles.
pub trait RuleProvider: Send + Sync {
    fn provider_id(&self) -> &'static str;

    /// Load or refresh rules from backing storage.
    ///
    /// Return value is number of active rules after successful refresh.
    fn refresh(&mut self) -> Result<usize, String>;
}
