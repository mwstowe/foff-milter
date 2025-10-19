use crate::config::Config;
use crate::detection::{
    brand_impersonation::BrandImpersonationDetector,
    health_spam::HealthSpamDetector,
    suspicious_domains::SuspiciousDomainDetector,
    DetectionResult,
};
use anyhow::Result;
use std::path::Path;

pub struct ModuleManager {
    pub suspicious_domains: Option<SuspiciousDomainDetector>,
    pub brand_impersonation: Option<BrandImpersonationDetector>,
    pub health_spam: Option<HealthSpamDetector>,
}

impl ModuleManager {
    pub fn new() -> Self {
        Self {
            suspicious_domains: None,
            brand_impersonation: None,
            health_spam: None,
        }
    }

    pub fn load_modules(config: &Config) -> Result<Self> {
        let mut manager = Self::new();
        let config_dir = &config.detection.config_dir;

        for module_name in &config.detection.enabled_modules {
            match module_name.as_str() {
                "suspicious-domains" => {
                    let path = Path::new(config_dir).join("suspicious-domains.yaml");
                    if path.exists() {
                        match SuspiciousDomainDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.suspicious_domains = Some(detector);
                                log::info!("Loaded suspicious-domains detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load suspicious-domains module: {}", e);
                                return Err(anyhow::anyhow!("Failed to load suspicious-domains module: {}", e));
                            }
                        }
                    } else {
                        log::warn!("suspicious-domains.yaml not found, skipping module");
                    }
                }
                "brand-impersonation" => {
                    let path = Path::new(config_dir).join("brand-impersonation.yaml");
                    if path.exists() {
                        match BrandImpersonationDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.brand_impersonation = Some(detector);
                                log::info!("Loaded brand-impersonation detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load brand-impersonation module: {}", e);
                                return Err(anyhow::anyhow!("Failed to load brand-impersonation module: {}", e));
                            }
                        }
                    } else {
                        log::warn!("brand-impersonation.yaml not found, skipping module");
                    }
                }
                "health-spam" => {
                    let path = Path::new(config_dir).join("health-spam.yaml");
                    if path.exists() {
                        match HealthSpamDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.health_spam = Some(detector);
                                log::info!("Loaded health-spam detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load health-spam module: {}", e);
                                return Err(anyhow::anyhow!("Failed to load health-spam module: {}", e));
                            }
                        }
                    } else {
                        log::warn!("health-spam.yaml not found, skipping module");
                    }
                }
                _ => {
                    log::warn!("Unknown detection module: {}", module_name);
                }
            }
        }

        Ok(manager)
    }

    pub fn check_email(&self, email_data: &EmailData) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        // Check suspicious domains
        if let Some(detector) = &self.suspicious_domains {
            if let Some(domain) = extract_domain(&email_data.sender) {
                let result = detector.check_domain(&domain);
                if result.matched {
                    results.push(result);
                }
            }
        }

        // Check brand impersonation
        if let Some(detector) = &self.brand_impersonation {
            if let Some(domain) = extract_domain(&email_data.sender) {
                let result = detector.check_brand_impersonation(&email_data.from_header, &domain);
                if result.matched {
                    results.push(result);
                }
            }
        }

        // Check health spam
        if let Some(detector) = &self.health_spam {
            if let Some(domain) = extract_domain(&email_data.sender) {
                let result = detector.check_health_spam(&email_data.subject, &email_data.body, &domain);
                if result.matched {
                    results.push(result);
                }
            }
        }

        results
    }

    pub fn get_total_confidence(&self, results: &[DetectionResult]) -> u32 {
        results.iter().map(|r| r.confidence).sum()
    }
}

#[derive(Debug, Clone)]
pub struct EmailData {
    pub sender: String,
    pub from_header: String,
    pub subject: String,
    pub body: String,
    pub recipients: Vec<String>,
}

impl EmailData {
    pub fn new(sender: String, from_header: String, subject: String, body: String, recipients: Vec<String>) -> Self {
        Self {
            sender,
            from_header,
            subject,
            body,
            recipients,
        }
    }
}

fn extract_domain(email: &str) -> Option<String> {
    if let Some(at_pos) = email.rfind('@') {
        let domain = &email[at_pos + 1..];
        // Remove angle brackets if present
        let domain = domain.trim_end_matches('>');
        Some(domain.to_string())
    } else {
        None
    }
}
