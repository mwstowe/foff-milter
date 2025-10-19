use super::DetectionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SuspiciousDomainConfig {
    pub suspicious_tlds: SuspiciousTlds,
    pub domain_age: DomainAgeConfig,
    pub suspicious_hosting: SuspiciousHostingConfig,
    pub confidence_scoring: ConfidenceScoring,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SuspiciousTlds {
    pub high_risk: Vec<String>,
    pub medium_risk: Vec<String>,
    pub low_risk: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DomainAgeConfig {
    pub max_age_days: u32,
    pub check_sender: bool,
    pub check_reply_to: bool,
    pub timeout_seconds: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SuspiciousHostingConfig {
    pub patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConfidenceScoring {
    pub high_risk_tld: u32,
    pub medium_risk_tld: u32,
    pub low_risk_tld: u32,
    pub young_domain: u32,
    pub suspicious_hosting: u32,
}

pub struct SuspiciousDomainDetector {
    config: SuspiciousDomainConfig,
}

impl SuspiciousDomainDetector {
    pub fn new(config: SuspiciousDomainConfig) -> Self {
        Self { config }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: SuspiciousDomainConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn check_domain(&self, domain: &str) -> DetectionResult {
        let mut confidence = 0;
        let mut reasons = Vec::new();

        // Check TLD risk level
        if let Some(tld) = domain.split('.').last() {
            if self.config.suspicious_tlds.high_risk.contains(&tld.to_string()) {
                confidence += self.config.confidence_scoring.high_risk_tld;
                reasons.push(format!("High-risk TLD: .{}", tld));
            } else if self.config.suspicious_tlds.medium_risk.contains(&tld.to_string()) {
                confidence += self.config.confidence_scoring.medium_risk_tld;
                reasons.push(format!("Medium-risk TLD: .{}", tld));
            } else if self.config.suspicious_tlds.low_risk.contains(&tld.to_string()) {
                confidence += self.config.confidence_scoring.low_risk_tld;
                reasons.push(format!("Low-risk TLD: .{}", tld));
            }
        }

        // Check hosting patterns
        for pattern in &self.config.suspicious_hosting.patterns {
            if domain.contains(pattern) {
                confidence += self.config.confidence_scoring.suspicious_hosting;
                reasons.push(format!("Suspicious hosting: {}", pattern));
            }
        }

        let matched = confidence > 0;
        let reason = if reasons.is_empty() {
            "No suspicious domain indicators".to_string()
        } else {
            reasons.join(", ")
        };

        DetectionResult::new(matched, confidence, reason, "SuspiciousDomain".to_string())
    }

    pub fn get_all_suspicious_tlds(&self) -> Vec<String> {
        let mut all_tlds = Vec::new();
        all_tlds.extend(self.config.suspicious_tlds.high_risk.clone());
        all_tlds.extend(self.config.suspicious_tlds.medium_risk.clone());
        all_tlds.extend(self.config.suspicious_tlds.low_risk.clone());
        all_tlds
    }
}
