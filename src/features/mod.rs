pub mod context_analyzer;
pub mod invoice_analyzer;
pub mod link_analyzer;
pub mod sender_alignment;

use crate::MailContext;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Case-insensitive header lookup utility function
pub fn get_header_case_insensitive<'a>(
    headers: &'a HashMap<String, String>,
    header_name: &str,
) -> Option<&'a String> {
    let header_lower = header_name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == header_lower)
        .map(|(_, v)| v)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureScore {
    pub feature_name: String,
    pub score: i32,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureAnalysis {
    pub scores: Vec<FeatureScore>,
    pub total_score: i32,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub trait FeatureExtractor: Send + Sync {
    fn extract(&self, context: &MailContext) -> FeatureScore;
    fn name(&self) -> &str;
}

pub struct FeatureEngine {
    extractors: Vec<Box<dyn FeatureExtractor>>,
}

impl Default for FeatureEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureEngine {
    pub fn new() -> Self {
        Self::from_config_dir("features").unwrap_or_else(|e| {
            log::warn!("Failed to load feature config, using defaults: {}", e);
            Self::default_config()
        })
    }

    pub fn from_config_dir(config_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Try to load feature configurations from TOML files
        let config_path = format!("{}/feature_scoring.toml", config_dir);

        if std::path::Path::new(&config_path).exists() {
            let config = crate::config_loader::ConfigLoader::load_feature_scoring(config_dir)?;
            Ok(Self::from_config(config))
        } else {
            log::warn!(
                "Feature config file not found: {}, using defaults",
                config_path
            );
            Ok(Self::default_config())
        }
    }

    fn from_config(config: crate::config_loader::FeatureScoringConfig) -> Self {
        Self {
            extractors: vec![
                Box::new(link_analyzer::LinkAnalyzer::from_config(
                    &config.feature_scoring.link_analysis,
                )),
                Box::new(sender_alignment::SenderAlignmentAnalyzer::from_config(
                    &config.feature_scoring.sender_alignment,
                )),
                Box::new(context_analyzer::ContextAnalyzer::from_config(
                    &config.feature_scoring.context_analysis,
                )),
                Box::new(invoice_analyzer::InvoiceAnalyzer::from_config(
                    &config.feature_scoring.invoice_analysis,
                )),
            ],
        }
    }

    fn default_config() -> Self {
        Self {
            extractors: vec![
                Box::new(link_analyzer::LinkAnalyzer::new()),
                Box::new(sender_alignment::SenderAlignmentAnalyzer::new()),
                Box::new(context_analyzer::ContextAnalyzer::new()),
                Box::new(invoice_analyzer::InvoiceAnalyzer::new()),
            ],
        }
    }

    pub fn analyze(&self, context: &MailContext) -> FeatureAnalysis {
        let mut scores = Vec::new();
        let mut total_score = 0;

        for extractor in &self.extractors {
            let score = extractor.extract(context);
            total_score += score.score;
            scores.push(score);
        }

        let risk_level = match total_score {
            score if score >= 100 => RiskLevel::Critical,
            score if score >= 50 => RiskLevel::High,
            score if score >= 20 => RiskLevel::Medium,
            _ => RiskLevel::Low,
        };

        FeatureAnalysis {
            scores,
            total_score,
            risk_level,
        }
    }
}
