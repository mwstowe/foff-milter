use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct DomainReputationConfig {
    pub financial_institutions: Vec<String>,
    pub email_service_providers: Vec<String>,
    pub suspicious_tlds: Vec<String>,
    pub legitimate_domains: Vec<String>,
    pub known_malicious: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DomainReputation {
    Trusted,              // Known legitimate domains
    Financial,            // Financial institutions
    EmailServiceProvider, // ESPs like SendGrid, Mailgun
    Suspicious,           // Suspicious TLDs or patterns
    Malicious,            // Known bad domains
    Unknown,              // Not categorized
}

#[derive(Debug, Clone)]
pub struct DomainReputationAnalyzer {
    #[allow(dead_code)]
    config: DomainReputationConfig,
    financial_domains: HashMap<String, bool>,
    esp_domains: HashMap<String, bool>,
    suspicious_tlds: HashMap<String, bool>,
    legitimate_domains: HashMap<String, bool>,
    malicious_domains: HashMap<String, bool>,
}

impl DomainReputationAnalyzer {
    pub fn new(config: DomainReputationConfig) -> Self {
        let mut analyzer = Self {
            financial_domains: HashMap::new(),
            esp_domains: HashMap::new(),
            suspicious_tlds: HashMap::new(),
            legitimate_domains: HashMap::new(),
            malicious_domains: HashMap::new(),
            config: config.clone(),
        };

        // Build lookup tables for performance
        for domain in &config.financial_institutions {
            analyzer
                .financial_domains
                .insert(domain.to_lowercase(), true);
        }

        for domain in &config.email_service_providers {
            analyzer.esp_domains.insert(domain.to_lowercase(), true);
        }

        for tld in &config.suspicious_tlds {
            analyzer.suspicious_tlds.insert(tld.to_lowercase(), true);
        }

        for domain in &config.legitimate_domains {
            analyzer
                .legitimate_domains
                .insert(domain.to_lowercase(), true);
        }

        for domain in &config.known_malicious {
            analyzer
                .malicious_domains
                .insert(domain.to_lowercase(), true);
        }

        analyzer
    }

    /// Analyze domain reputation from email address
    pub fn analyze_email_domain(&self, email: &str) -> DomainReputation {
        if let Some(domain) = self.extract_domain(email) {
            self.analyze_domain(&domain)
        } else {
            DomainReputation::Unknown
        }
    }

    /// Analyze domain reputation directly
    pub fn analyze_domain(&self, domain: &str) -> DomainReputation {
        let domain_lower = domain.to_lowercase();

        // Check for known malicious first
        if self.malicious_domains.contains_key(&domain_lower) {
            return DomainReputation::Malicious;
        }

        // Check for financial institutions
        if self.is_financial_domain(&domain_lower) {
            return DomainReputation::Financial;
        }

        // Check for ESPs
        if self.is_esp_domain(&domain_lower) {
            return DomainReputation::EmailServiceProvider;
        }

        // Check for legitimate domains
        if self.legitimate_domains.contains_key(&domain_lower) {
            return DomainReputation::Trusted;
        }

        // Check for suspicious TLDs
        if self.has_suspicious_tld(&domain_lower) {
            return DomainReputation::Suspicious;
        }

        DomainReputation::Unknown
    }

    /// Check if domain is a financial institution
    pub fn is_financial_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Direct match
        if self.financial_domains.contains_key(&domain_lower) {
            return true;
        }

        // Check subdomains of financial institutions
        for financial_domain in self.financial_domains.keys() {
            if domain_lower.ends_with(&format!(".{}", financial_domain)) {
                return true;
            }
        }

        false
    }

    /// Check if domain is an ESP
    pub fn is_esp_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Direct match
        if self.esp_domains.contains_key(&domain_lower) {
            return true;
        }

        // Check subdomains of ESPs
        for esp_domain in self.esp_domains.keys() {
            if domain_lower.ends_with(&format!(".{}", esp_domain)) {
                return true;
            }
        }

        false
    }

    /// Check if domain has suspicious TLD
    pub fn has_suspicious_tld(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        for tld in self.suspicious_tlds.keys() {
            if domain_lower.ends_with(&format!(".{}", tld)) {
                return true;
            }
        }

        false
    }

    /// Check if sender domain matches claimed brand
    pub fn validate_brand_alignment(&self, sender_domain: &str, claimed_brand: &str) -> bool {
        let sender_lower = sender_domain.to_lowercase();
        let brand_lower = claimed_brand.to_lowercase();

        // Direct brand match in domain
        if sender_lower.contains(&brand_lower) {
            return true;
        }

        // Check if it's a legitimate ESP sending for the brand
        if self.is_esp_domain(&sender_lower) {
            // ESPs can legitimately send for any brand
            return true;
        }

        // Check if it's a known legitimate domain for this brand
        // This would need brand-specific configuration
        false
    }

    /// Extract domain from email address
    fn extract_domain(&self, email: &str) -> Option<String> {
        email.split('@').nth(1).map(|s| s.to_string())
    }

    /// Get reputation score for domain (for scoring systems)
    pub fn get_reputation_score(&self, domain: &str) -> i32 {
        match self.analyze_domain(domain) {
            DomainReputation::Trusted => -20,   // Boost legitimate domains
            DomainReputation::Financial => -15, // Boost financial institutions
            DomainReputation::EmailServiceProvider => -10, // Slight boost for ESPs
            DomainReputation::Unknown => 0,     // Neutral
            DomainReputation::Suspicious => 30, // Penalize suspicious
            DomainReputation::Malicious => 100, // Heavy penalty for malicious
        }
    }
}

/// Feature extractor implementation for domain reputation
pub struct DomainReputationFeature {
    analyzer: DomainReputationAnalyzer,
}

impl Default for DomainReputationFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainReputationFeature {
    pub fn new() -> Self {
        // Load default configuration
        let config = DomainReputationConfig {
            financial_institutions: vec![
                "chase.com".to_string(),
                "paypal.com".to_string(),
                "wellsfargo.com".to_string(),
                "bankofamerica.com".to_string(),
                "citi.com".to_string(),
            ],
            email_service_providers: vec![
                "sendgrid.net".to_string(),
                "mailgun.org".to_string(),
                "mailchimp.com".to_string(),
            ],
            suspicious_tlds: vec![
                "tk".to_string(),
                "ml".to_string(),
                "shop".to_string(),
                "icu".to_string(),
            ],
            legitimate_domains: vec![
                "google.com".to_string(),
                "microsoft.com".to_string(),
                "apple.com".to_string(),
            ],
            known_malicious: vec![],
        };

        Self {
            analyzer: DomainReputationAnalyzer::new(config),
        }
    }

    pub fn from_config(config: DomainReputationConfig) -> Self {
        Self {
            analyzer: DomainReputationAnalyzer::new(config),
        }
    }
}

impl FeatureExtractor for DomainReputationFeature {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();
        let mut confidence = 0.0f32;

        // Analyze sender domain
        if let Some(sender) = &context.sender {
            if let Some(domain) = self.analyzer.extract_domain(sender) {
                let reputation = self.analyzer.analyze_domain(&domain);
                let domain_score = self.analyzer.get_reputation_score(&domain);

                score += domain_score;
                confidence += 0.8; // High confidence in domain analysis

                match reputation {
                    DomainReputation::Trusted => {
                        evidence.push(format!("Trusted domain: {}", domain));
                    }
                    DomainReputation::Financial => {
                        evidence.push(format!("Financial institution: {}", domain));
                    }
                    DomainReputation::EmailServiceProvider => {
                        evidence.push(format!("Email service provider: {}", domain));
                    }
                    DomainReputation::Suspicious => {
                        evidence.push(format!("Suspicious domain: {}", domain));
                    }
                    DomainReputation::Malicious => {
                        evidence.push(format!("Malicious domain: {}", domain));
                    }
                    DomainReputation::Unknown => {
                        evidence.push(format!("Unknown domain reputation: {}", domain));
                    }
                }
            }
        }

        // Analyze Return-Path domain if different
        if let Some(return_path) = context.headers.get("return-path") {
            if let Some(domain) = self.analyzer.extract_domain(return_path) {
                let reputation = self.analyzer.analyze_domain(&domain);
                if reputation == DomainReputation::Suspicious
                    || reputation == DomainReputation::Malicious
                {
                    let domain_score = self.analyzer.get_reputation_score(&domain);
                    score += domain_score / 2; // Reduced weight for Return-Path
                    evidence.push(format!("Suspicious Return-Path domain: {}", domain));
                    confidence += 0.6;
                }
            }
        }

        FeatureScore {
            feature_name: "Domain Reputation".to_string(),
            score,
            confidence: confidence.min(1.0),
            evidence,
        }
    }

    fn name(&self) -> &str {
        "Domain Reputation"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> DomainReputationConfig {
        DomainReputationConfig {
            financial_institutions: vec![
                "chase.com".to_string(),
                "paypal.com".to_string(),
                "wellsfargo.com".to_string(),
            ],
            email_service_providers: vec![
                "sendgrid.net".to_string(),
                "mailgun.org".to_string(),
                "mailchimp.com".to_string(),
            ],
            suspicious_tlds: vec!["tk".to_string(), "ml".to_string(), "shop".to_string()],
            legitimate_domains: vec!["google.com".to_string(), "microsoft.com".to_string()],
            known_malicious: vec!["malicious.com".to_string()],
        }
    }

    #[test]
    fn test_financial_domain_detection() {
        let analyzer = DomainReputationAnalyzer::new(create_test_config());

        assert_eq!(
            analyzer.analyze_domain("chase.com"),
            DomainReputation::Financial
        );
        assert_eq!(
            analyzer.analyze_domain("mail.chase.com"),
            DomainReputation::Financial
        );
        assert_eq!(
            analyzer.analyze_email_domain("user@paypal.com"),
            DomainReputation::Financial
        );
    }

    #[test]
    fn test_esp_domain_detection() {
        let analyzer = DomainReputationAnalyzer::new(create_test_config());

        assert_eq!(
            analyzer.analyze_domain("sendgrid.net"),
            DomainReputation::EmailServiceProvider
        );
        assert_eq!(
            analyzer.analyze_domain("bounce.sendgrid.net"),
            DomainReputation::EmailServiceProvider
        );
    }

    #[test]
    fn test_suspicious_tld_detection() {
        let analyzer = DomainReputationAnalyzer::new(create_test_config());

        assert_eq!(
            analyzer.analyze_domain("suspicious.tk"),
            DomainReputation::Suspicious
        );
        assert_eq!(
            analyzer.analyze_domain("fake.shop"),
            DomainReputation::Suspicious
        );
    }

    #[test]
    fn test_malicious_domain_detection() {
        let analyzer = DomainReputationAnalyzer::new(create_test_config());

        assert_eq!(
            analyzer.analyze_domain("malicious.com"),
            DomainReputation::Malicious
        );
    }

    #[test]
    fn test_reputation_scoring() {
        let analyzer = DomainReputationAnalyzer::new(create_test_config());

        assert_eq!(analyzer.get_reputation_score("chase.com"), -15);
        assert_eq!(analyzer.get_reputation_score("sendgrid.net"), -10);
        assert_eq!(analyzer.get_reputation_score("suspicious.tk"), 30);
        assert_eq!(analyzer.get_reputation_score("malicious.com"), 100);
    }
}
