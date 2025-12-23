use crate::dkim_verification::{DkimAuthStatus, DkimVerifier, DomainAlignment};
use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum AuthenticationRisk {
    Secure,     // All authentication methods pass
    Standard,   // Some authentication methods pass
    Suspicious, // Mixed authentication results
    Insecure,   // No or failed authentication
    Spoofed,    // Clear signs of spoofing
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationConfig {
    pub trusted_domains: Vec<String>, // Domains that should always have auth
    pub esp_domains: Vec<String>,     // ESP domains with special handling
    pub suspicious_patterns: Vec<String>, // Patterns indicating auth bypass attempts
    pub scoring: AuthenticationScoring,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationScoring {
    pub dkim_pass_boost: i32,
    pub spf_pass_boost: i32,
    pub dmarc_pass_boost: i32,
    pub auth_failure_penalty: i32,
    pub spoofing_penalty: i32,
    pub missing_auth_penalty: i32,
}

#[derive(Debug, Clone)]
pub struct AuthenticationAnalyzer {
    config: AuthenticationConfig,
}

impl AuthenticationAnalyzer {
    pub fn new(config: AuthenticationConfig) -> Self {
        Self { config }
    }

    /// Comprehensive authentication analysis
    pub fn analyze_authentication(
        &self,
        context: &MailContext,
    ) -> (AuthenticationRisk, i32, Vec<String>) {
        let mut score = 0;
        let mut evidence = Vec::new();
        let mut risk_factors = 0;

        // Extract sender domain
        let sender_domain = if let Some(sender) = &context.sender {
            self.extract_domain(sender).unwrap_or_default()
        } else {
            return (
                AuthenticationRisk::Insecure,
                self.config.scoring.missing_auth_penalty,
                vec!["No sender information available".to_string()],
            );
        };

        // Analyze DKIM
        let dkim_result = DkimVerifier::verify(&context.headers, Some(&sender_domain));
        match dkim_result.auth_status {
            DkimAuthStatus::Pass => {
                score += self.config.scoring.dkim_pass_boost;
                evidence.push("DKIM authentication passed".to_string());

                // Check domain alignment
                match dkim_result.domain_alignment {
                    DomainAlignment::Aligned => {
                        evidence.push("DKIM domain properly aligned".to_string());
                    }
                    DomainAlignment::Misaligned {
                        dkim_domain,
                        sender_domain,
                    } => {
                        evidence.push(format!(
                            "DKIM domain misaligned: {} vs {}",
                            dkim_domain, sender_domain
                        ));
                        risk_factors += 1;
                    }
                    DomainAlignment::Unknown => {
                        evidence.push("DKIM domain alignment unknown".to_string());
                        risk_factors += 1;
                    }
                }
            }
            DkimAuthStatus::Fail(reason) => {
                score += self.config.scoring.auth_failure_penalty;
                evidence.push(format!("DKIM authentication failed: {}", reason));
                risk_factors += 2;
            }
            DkimAuthStatus::None => {
                evidence.push("No DKIM signature found".to_string());
                if self.should_have_dkim(&sender_domain) {
                    score += self.config.scoring.missing_auth_penalty;
                    risk_factors += 1;
                }
            }
            DkimAuthStatus::TempError => {
                evidence.push("DKIM temporary error".to_string());
                risk_factors += 1;
            }
            DkimAuthStatus::PermError => {
                evidence.push("DKIM permanent error".to_string());
                risk_factors += 2;
            }
        }

        // Analyze SPF
        let spf_result = self.analyze_spf(&context.headers);
        match spf_result {
            SpfResult::Pass => {
                score += self.config.scoring.spf_pass_boost;
                evidence.push("SPF authentication passed".to_string());
            }
            SpfResult::Fail => {
                score += self.config.scoring.auth_failure_penalty;
                evidence.push("SPF authentication failed".to_string());
                risk_factors += 2;
            }
            SpfResult::SoftFail => {
                evidence.push("SPF soft fail".to_string());
                risk_factors += 1;
            }
            SpfResult::None => {
                evidence.push("No SPF record found".to_string());
                if self.should_have_spf(&sender_domain) {
                    score += self.config.scoring.missing_auth_penalty / 2;
                    risk_factors += 1;
                }
            }
            SpfResult::Unknown => {
                evidence.push("SPF result unknown".to_string());
            }
        }

        // Analyze DMARC
        let dmarc_result = self.analyze_dmarc(&context.headers);
        match dmarc_result {
            DmarcResult::Pass => {
                score += self.config.scoring.dmarc_pass_boost;
                evidence.push("DMARC authentication passed".to_string());
            }
            DmarcResult::Fail => {
                score += self.config.scoring.auth_failure_penalty;
                evidence.push("DMARC authentication failed".to_string());
                risk_factors += 2;
            }
            DmarcResult::None => {
                evidence.push("No DMARC policy found".to_string());
            }
            DmarcResult::Unknown => {
                evidence.push("DMARC result unknown".to_string());
            }
        }

        // Check for spoofing indicators
        let spoofing_score = self.detect_spoofing_attempts(context);
        if spoofing_score > 0 {
            score += spoofing_score;
            evidence.push("Potential spoofing attempt detected".to_string());
            risk_factors += 3;
        }

        // Determine overall risk level
        let risk_level = match risk_factors {
            0 => AuthenticationRisk::Secure,
            1..=2 => AuthenticationRisk::Standard,
            3..=4 => AuthenticationRisk::Suspicious,
            5..=6 => AuthenticationRisk::Insecure,
            _ => AuthenticationRisk::Spoofed,
        };

        (risk_level, score, evidence)
    }

    /// Check if domain should have DKIM
    fn should_have_dkim(&self, domain: &str) -> bool {
        // Major domains and ESPs should have DKIM
        self.config
            .trusted_domains
            .iter()
            .any(|d| domain.contains(d))
            || self.config.esp_domains.iter().any(|d| domain.contains(d))
            || self.is_major_domain(domain)
    }

    /// Check if domain should have SPF
    fn should_have_spf(&self, domain: &str) -> bool {
        // Most legitimate domains should have SPF
        self.is_major_domain(domain)
            || self
                .config
                .trusted_domains
                .iter()
                .any(|d| domain.contains(d))
    }

    /// Check if it's a major domain that should have authentication
    fn is_major_domain(&self, domain: &str) -> bool {
        let major_domains = [
            "gmail.com",
            "outlook.com",
            "yahoo.com",
            "hotmail.com",
            "amazon.com",
            "microsoft.com",
            "google.com",
            "apple.com",
            "paypal.com",
            "ebay.com",
            "facebook.com",
            "twitter.com",
        ];

        major_domains.iter().any(|&major| domain.ends_with(major))
    }

    /// Analyze SPF results from headers
    fn analyze_spf(&self, headers: &HashMap<String, String>) -> SpfResult {
        for (key, value) in headers {
            if key.to_lowercase() == "authentication-results" {
                let value_lower = value.to_lowercase();
                if value_lower.contains("spf=pass") {
                    return SpfResult::Pass;
                } else if value_lower.contains("spf=fail") {
                    return SpfResult::Fail;
                } else if value_lower.contains("spf=softfail") {
                    return SpfResult::SoftFail;
                } else if value_lower.contains("spf=none") {
                    return SpfResult::None;
                }
            }
        }
        SpfResult::Unknown
    }

    /// Analyze DMARC results from headers
    fn analyze_dmarc(&self, headers: &HashMap<String, String>) -> DmarcResult {
        for (key, value) in headers {
            if key.to_lowercase() == "authentication-results" {
                let value_lower = value.to_lowercase();
                if value_lower.contains("dmarc=pass") {
                    return DmarcResult::Pass;
                } else if value_lower.contains("dmarc=fail") {
                    return DmarcResult::Fail;
                } else if value_lower.contains("dmarc=none") {
                    return DmarcResult::None;
                }
            }
        }
        DmarcResult::Unknown
    }

    /// Detect potential spoofing attempts
    fn detect_spoofing_attempts(&self, context: &MailContext) -> i32 {
        let mut spoofing_score = 0;

        // Check for suspicious patterns in headers
        for pattern in &self.config.suspicious_patterns {
            if let Some(subject) = context.headers.get("subject") {
                if subject.to_lowercase().contains(&pattern.to_lowercase()) {
                    spoofing_score += 20;
                }
            }
        }

        // Check for Reply-To mismatch with From
        if let Some(from) = context.headers.get("from") {
            if let Some(reply_to) = context.headers.get("reply-to") {
                if self.extract_domain(from) != self.extract_domain(reply_to) {
                    // Different domains in From and Reply-To can indicate spoofing
                    spoofing_score += 15;
                }
            }
        }

        spoofing_score
    }

    /// Extract domain from email address
    fn extract_domain(&self, email: &str) -> Option<String> {
        email.split('@').nth(1).map(|s| s.to_string())
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    None,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
enum DmarcResult {
    Pass,
    Fail,
    None,
    Unknown,
}

/// Feature extractor for enhanced authentication analysis
pub struct AuthenticationFeature {
    analyzer: AuthenticationAnalyzer,
}

impl Default for AuthenticationFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthenticationFeature {
    pub fn new() -> Self {
        let config = AuthenticationConfig {
            trusted_domains: vec![
                "gov".to_string(),
                "edu".to_string(),
                "mil".to_string(),
                "bank".to_string(),
                "paypal.com".to_string(),
                "amazon.com".to_string(),
            ],
            esp_domains: vec![
                "sendgrid.net".to_string(),
                "mailgun.org".to_string(),
                "mailchimp.com".to_string(),
                "amazonses.com".to_string(),
            ],
            suspicious_patterns: vec![
                "verify account".to_string(),
                "suspended".to_string(),
                "urgent action".to_string(),
                "click here".to_string(),
            ],
            scoring: AuthenticationScoring {
                dkim_pass_boost: -10,
                spf_pass_boost: -5,
                dmarc_pass_boost: -15,
                auth_failure_penalty: 25,
                spoofing_penalty: 40,
                missing_auth_penalty: 15,
            },
        };

        Self {
            analyzer: AuthenticationAnalyzer::new(config),
        }
    }

    pub fn from_config(config: AuthenticationConfig) -> Self {
        Self {
            analyzer: AuthenticationAnalyzer::new(config),
        }
    }
}

impl FeatureExtractor for AuthenticationFeature {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let (risk_level, score, evidence) = self.analyzer.analyze_authentication(context);

        let confidence = match risk_level {
            AuthenticationRisk::Secure => 0.9,
            AuthenticationRisk::Standard => 0.8,
            AuthenticationRisk::Suspicious => 0.85,
            AuthenticationRisk::Insecure => 0.9,
            AuthenticationRisk::Spoofed => 0.95,
        };

        let mut final_evidence = evidence;
        final_evidence.push(format!("Authentication risk level: {:?}", risk_level));

        FeatureScore {
            feature_name: "Authentication Analysis".to_string(),
            score,
            confidence,
            evidence: final_evidence,
        }
    }

    fn name(&self) -> &str {
        "Authentication Analysis"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> AuthenticationConfig {
        AuthenticationConfig {
            trusted_domains: vec!["example.com".to_string()],
            esp_domains: vec!["sendgrid.net".to_string()],
            suspicious_patterns: vec!["urgent".to_string()],
            scoring: AuthenticationScoring {
                dkim_pass_boost: -10,
                spf_pass_boost: -5,
                dmarc_pass_boost: -15,
                auth_failure_penalty: 25,
                spoofing_penalty: 40,
                missing_auth_penalty: 15,
            },
        }
    }

    #[test]
    fn test_domain_extraction() {
        let analyzer = AuthenticationAnalyzer::new(create_test_config());

        assert_eq!(
            analyzer.extract_domain("user@example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(analyzer.extract_domain("invalid"), None);
    }

    #[test]
    fn test_major_domain_detection() {
        let analyzer = AuthenticationAnalyzer::new(create_test_config());

        assert!(analyzer.is_major_domain("gmail.com"));
        assert!(analyzer.is_major_domain("mail.gmail.com"));
        assert!(!analyzer.is_major_domain("fake.com"));
    }

    #[test]
    fn test_should_have_auth() {
        let analyzer = AuthenticationAnalyzer::new(create_test_config());

        assert!(analyzer.should_have_dkim("gmail.com"));
        assert!(analyzer.should_have_dkim("sendgrid.net"));
        assert!(analyzer.should_have_spf("example.com"));
    }
}
