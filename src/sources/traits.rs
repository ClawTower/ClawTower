// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

use std::collections::HashMap;

/// Normalized source event used by source adapters before detector routing.
#[derive(Debug, Clone)]
pub struct SourceEvent {
    pub source: String,
    pub kind: String,
    pub fields: HashMap<String, String>,
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceHealth {
    Healthy,
    Degraded,
    Failed,
}

/// Source adapter contract for auditd/network/journald/etc.
///
/// Phase 1 scaffolding: this trait is introduced for future runtime registry use.
pub trait EventSource: Send + Sync {
    fn id(&self) -> &'static str;
    fn source_type(&self) -> &'static str;

    /// Start source processing loop.
    ///
    /// Implementations may spawn background tasks, but callers remain responsible
    /// for lifecycle ownership and shutdown signaling.
    fn start(&mut self) -> Result<(), String>;

    /// Return best-effort health state for status endpoints and dashboards.
    fn health(&self) -> SourceHealth {
        SourceHealth::Healthy
    }
}
