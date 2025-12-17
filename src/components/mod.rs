//! Simplified architectural components for FOFF Milter
//! 
//! This module contains the new simplified architecture components that will
//! eventually replace the scattered logic in the current system.

pub mod authentication_analyzer;
pub mod context_analyzer_v2;
pub mod decision_engine;
pub mod early_decision_engine;
pub mod email_normalizer_v2;
pub mod filter_engine_v2;
pub mod hybrid_filter_engine;
pub mod mismatch_analyzer;

#[cfg(test)]
pub mod benchmark;
#[cfg(test)]
pub mod migration_test;

// TODO: Create rule_engine_v2 component
// pub mod rule_engine_v2;

use crate::MailContext;
use serde::{Deserialize, Serialize};

/// Common result type for component analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentResult {
    pub component_name: String,
    pub score: i32,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub action_recommended: Option<ComponentAction>,
}

/// Actions that components can recommend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComponentAction {
    Accept,
    Tag,
    Reject,
    Continue, // Continue to next component
}

/// Trait for all analysis components
pub trait AnalysisComponent: Send + Sync {
    fn analyze(&self, context: &MailContext) -> ComponentResult;
    fn name(&self) -> &str;
    fn priority(&self) -> u8; // Lower number = higher priority
}
