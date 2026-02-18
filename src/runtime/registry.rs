// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

use std::collections::BTreeMap;

use crate::detect::traits::Detector;
use crate::sources::traits::EventSource;

/// Registry scaffold for dynamic detector/source composition.
///
/// Phase 1: this registry is intentionally not wired into main runtime flow yet.
/// It exists to enable incremental migration with minimal risk.
#[derive(Default)]
pub struct RuntimeRegistry {
    detectors: BTreeMap<String, Box<dyn Detector>>,
    sources: BTreeMap<String, Box<dyn EventSource>>,
}

impl RuntimeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_detector(&mut self, detector: Box<dyn Detector>) -> Result<(), String> {
        let id = detector.id().to_string();
        if self.detectors.contains_key(&id) {
            return Err(format!("detector already registered: {id}"));
        }
        self.detectors.insert(id, detector);
        Ok(())
    }

    pub fn register_source(&mut self, source: Box<dyn EventSource>) -> Result<(), String> {
        let id = source.id().to_string();
        if self.sources.contains_key(&id) {
            return Err(format!("source already registered: {id}"));
        }
        self.sources.insert(id, source);
        Ok(())
    }

    pub fn detector_ids(&self) -> Vec<String> {
        self.detectors.keys().cloned().collect()
    }

    pub fn source_ids(&self) -> Vec<String> {
        self.sources.keys().cloned().collect()
    }

    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}
