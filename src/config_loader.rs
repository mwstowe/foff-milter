use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LegitimateDomainsConfig {
    pub legitimate_domains: HashMap<String, Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FeatureScoringConfig {
    pub feature_scoring: FeatureScoring,
    pub spam_thresholds: SpamThresholds,
    pub rule_scoring: HashMap<String, HashMap<String, i32>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FeatureScoring {
    pub link_analysis: LinkAnalysisConfig,
    pub sender_alignment: SenderAlignmentConfig,
    pub context_analysis: ContextAnalysisConfig,
    pub invoice_analysis: InvoiceAnalysisConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LinkAnalysisConfig {
    pub base_score: i32,
    pub confidence_threshold: f64,
    pub suspicious_patterns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SenderAlignmentConfig {
    pub base_score: i32,
    pub confidence_threshold: f64,
    pub job_related_exclusion: bool,
    pub job_indicators: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContextAnalysisConfig {
    pub base_score: i32,
    pub confidence_threshold: f64,
    pub urgency_patterns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InvoiceAnalysisConfig {
    pub base_score: i32,
    pub confidence_threshold: f64,
    pub scam_indicators: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpamThresholds {
    pub accept: i32,
    pub tag_as_spam: i32,
    pub reject: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BrandPatternsConfig {
    pub brand_patterns: HashMap<String, HashMap<String, Vec<String>>>,
    pub exclusion_patterns: HashMap<String, Vec<String>>,
}

pub struct ConfigLoader;

impl ConfigLoader {
    pub fn reload() -> Result<(), Box<dyn std::error::Error>> {
        // Force reload of all config data by clearing any caches
        // Currently configs are loaded fresh each time, so this is a no-op
        // but provides hook for future caching implementations
        log::info!("ConfigLoader data refreshed");
        Ok(())
    }

    pub fn load_legitimate_domains() -> Result<LegitimateDomainsConfig, Box<dyn std::error::Error>>
    {
        let content = fs::read_to_string("config/legitimate_domains.yaml")?;
        Ok(serde_yml::from_str(&content)?)
    }

    pub fn load_feature_scoring() -> Result<FeatureScoringConfig, Box<dyn std::error::Error>> {
        let content = fs::read_to_string("config/feature_scoring.yaml")?;
        Ok(serde_yml::from_str(&content)?)
    }

    pub fn load_brand_patterns() -> Result<BrandPatternsConfig, Box<dyn std::error::Error>> {
        let content = fs::read_to_string("config/brand_patterns.yaml")?;
        Ok(serde_yml::from_str(&content)?)
    }

    pub fn get_all_legitimate_domains() -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let config = Self::load_legitimate_domains()?;
        let mut domains = Vec::new();

        for domain_list in config.legitimate_domains.values() {
            domains.extend(domain_list.clone());
        }

        Ok(domains)
    }
}
