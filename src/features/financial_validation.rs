use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct FinancialInstitution {
    pub domains: Vec<String>,
    pub aliases: Vec<String>, // Common names/aliases for the institution
}

#[derive(Debug, Clone, Deserialize)]
pub struct FinancialValidationConfig {
    pub institutions: HashMap<String, FinancialInstitution>,
    pub payment_processors: Vec<String>,
    pub phishing_keywords: Vec<String>,
    pub urgency_keywords: Vec<String>,
    pub financial_terms: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FinancialValidationAnalyzer {
    config: FinancialValidationConfig,
    institution_domains: HashMap<String, String>, // domain -> institution_name
    #[allow(dead_code)]
    institution_aliases: HashMap<String, String>, // alias -> institution_name
}

impl FinancialValidationAnalyzer {
    pub fn new(config: FinancialValidationConfig) -> Self {
        let mut institution_domains = HashMap::new();
        let mut institution_aliases = HashMap::new();

        // Build lookup tables
        for (institution_name, institution) in &config.institutions {
            // Map domains to institution
            for domain in &institution.domains {
                institution_domains.insert(domain.to_lowercase(), institution_name.clone());
            }

            // Map aliases to institution
            for alias in &institution.aliases {
                institution_aliases.insert(alias.to_lowercase(), institution_name.clone());
            }
        }

        Self {
            config,
            institution_domains,
            institution_aliases,
        }
    }

    /// Check if sender domain is legitimate for claimed financial institution
    pub fn validate_financial_sender(
        &self,
        sender_domain: &str,
        claimed_institution: &str,
    ) -> bool {
        let sender_lower = sender_domain.to_lowercase();
        let institution_lower = claimed_institution.to_lowercase();

        // Get legitimate domains for this institution
        if let Some(institution) = self.config.institutions.get(&institution_lower) {
            // Check direct domain match
            for domain in &institution.domains {
                let domain_lower = domain.to_lowercase();
                if sender_lower == domain_lower
                    || sender_lower.ends_with(&format!(".{}", domain_lower))
                {
                    return true;
                }
            }
        }

        false
    }

    /// Detect financial phishing attempts
    pub fn detect_financial_phishing(
        &self,
        content: &str,
        sender_domain: &str,
    ) -> Vec<(String, i32, String)> {
        let mut detections = Vec::new();
        let content_lower = content.to_lowercase();
        let sender_lower = sender_domain.to_lowercase();

        // Only flag if sender domain contains financial institution name (potential impersonation)
        // This prevents flagging legitimate mentions of financial institutions in content
        for institution_name in self.config.institutions.keys() {
            let institution_lower = institution_name.to_lowercase();

            // Check if sender domain contains the institution name (potential impersonation)
            if sender_lower.contains(&institution_lower)
                && !self.validate_financial_sender(&sender_lower, &institution_lower)
            {
                // This is a suspicious domain mimicking the financial institution
                let score = 50 + self.calculate_context_score(&content_lower);
                detections.push((
                    institution_name.clone(),
                    score,
                    format!(
                        "Suspicious domain mimicking financial institution: {} in {}",
                        institution_name, sender_domain
                    ),
                ));
            }
        }

        // Check for payment processor domain impersonation
        for processor in &self.config.payment_processors {
            if sender_lower.contains(&processor.to_lowercase())
                && !sender_lower.contains(&format!("{}.com", processor))
            {
                let score = 40 + self.calculate_context_score(&content_lower);
                detections.push((
                    processor.clone(),
                    score,
                    format!(
                        "Suspicious domain mimicking payment processor: {} in {}",
                        processor, sender_domain
                    ),
                ));
            }
        }

        detections
    }

    /// Calculate additional score based on suspicious context
    fn calculate_context_score(&self, content: &str) -> i32 {
        let mut score = 0;

        // Check for phishing keywords
        for keyword in &self.config.phishing_keywords {
            if content.contains(&keyword.to_lowercase()) {
                score += 30;
                break;
            }
        }

        // Check for urgency tactics
        for keyword in &self.config.urgency_keywords {
            if content.contains(&keyword.to_lowercase()) {
                score += 20;
                break;
            }
        }

        // Check for financial terms that are commonly used in phishing
        for term in &self.config.financial_terms {
            if content.contains(&term.to_lowercase()) {
                score += 15;
                break;
            }
        }

        score
    }

    /// Extract domain from email address
    fn extract_domain(&self, email: &str) -> Option<String> {
        email.split('@').nth(1).map(|s| s.to_string())
    }

    /// Get financial institution from domain if it's legitimate
    pub fn get_institution_from_domain(&self, domain: &str) -> Option<String> {
        let domain_lower = domain.to_lowercase();

        // Direct lookup
        if let Some(institution) = self.institution_domains.get(&domain_lower) {
            return Some(institution.clone());
        }

        // Check subdomains
        for (legitimate_domain, institution) in &self.institution_domains {
            if domain_lower.ends_with(&format!(".{}", legitimate_domain)) {
                return Some(institution.clone());
            }
        }

        None
    }

    /// Check if domain is a known financial institution
    pub fn is_financial_domain(&self, domain: &str) -> bool {
        self.get_institution_from_domain(domain).is_some()
    }
}

/// Feature extractor for financial institution validation
pub struct FinancialValidationFeature {
    analyzer: FinancialValidationAnalyzer,
}

impl Default for FinancialValidationFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl FinancialValidationFeature {
    pub fn new() -> Self {
        // Default configuration with major financial institutions
        let mut institutions = HashMap::new();

        institutions.insert(
            "chase".to_string(),
            FinancialInstitution {
                domains: vec![
                    "chase.com".to_string(),
                    "jpmorgan.com".to_string(),
                    "jpmorganchase.com".to_string(),
                ],
                aliases: vec!["jp morgan".to_string(), "jpmorgan chase".to_string()],
            },
        );

        institutions.insert(
            "wellsfargo".to_string(),
            FinancialInstitution {
                domains: vec!["wellsfargo.com".to_string(), "wf.com".to_string()],
                aliases: vec!["wells fargo".to_string()],
            },
        );

        institutions.insert(
            "bankofamerica".to_string(),
            FinancialInstitution {
                domains: vec!["bankofamerica.com".to_string(), "bofa.com".to_string()],
                aliases: vec!["bank of america".to_string(), "bofa".to_string()],
            },
        );

        institutions.insert(
            "citi".to_string(),
            FinancialInstitution {
                domains: vec![
                    "citi.com".to_string(),
                    "citicards.com".to_string(),
                    "info6.citi.com".to_string(),
                ],
                aliases: vec!["citibank".to_string(), "citicorp".to_string()],
            },
        );

        institutions.insert(
            "paypal".to_string(),
            FinancialInstitution {
                domains: vec![
                    "paypal.com".to_string(),
                    "paypal-communications.com".to_string(),
                ],
                aliases: vec!["pay pal".to_string()],
            },
        );

        institutions.insert(
            "americanexpress".to_string(),
            FinancialInstitution {
                domains: vec!["americanexpress.com".to_string(), "amex.com".to_string()],
                aliases: vec!["american express".to_string(), "amex".to_string()],
            },
        );

        let config = FinancialValidationConfig {
            institutions,
            payment_processors: vec![
                "stripe".to_string(),
                "square".to_string(),
                "venmo".to_string(),
                "zelle".to_string(),
            ],
            phishing_keywords: vec![
                "verify your account".to_string(),
                "account suspended".to_string(),
                "payment failed".to_string(),
                "card declined".to_string(),
                "suspicious activity".to_string(),
                "fraud alert".to_string(),
                "update payment method".to_string(),
                "confirm bank details".to_string(),
            ],
            urgency_keywords: vec![
                "immediate action required".to_string(),
                "urgent".to_string(),
                "expires today".to_string(),
                "act now".to_string(),
                "verify immediately".to_string(),
                "click here now".to_string(),
            ],
            financial_terms: vec![
                "account overdrawn".to_string(),
                "billing problem".to_string(),
                "transaction failed".to_string(),
                "security breach".to_string(),
                "unauthorized access".to_string(),
            ],
        };

        Self {
            analyzer: FinancialValidationAnalyzer::new(config),
        }
    }

    pub fn from_config(config: FinancialValidationConfig) -> Self {
        Self {
            analyzer: FinancialValidationAnalyzer::new(config),
        }
    }
}

impl FeatureExtractor for FinancialValidationFeature {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();
        let mut confidence = 0.0f32;

        // Get sender domain
        let sender_domain = if let Some(sender) = &context.sender {
            if let Some(domain) = self.analyzer.extract_domain(sender) {
                domain
            } else {
                return FeatureScore {
                    feature_name: "Financial Validation".to_string(),
                    score: 0,
                    confidence: 0.0,
                    evidence: vec!["No valid sender domain found".to_string()],
                };
            }
        } else {
            return FeatureScore {
                feature_name: "Financial Validation".to_string(),
                score: 0,
                confidence: 0.0,
                evidence: vec!["No sender found".to_string()],
            };
        };

        // Combine subject and body for analysis
        let mut content = String::new();
        if let Some(subject) = context.headers.get("subject") {
            content.push_str(subject);
            content.push(' ');
        }
        if let Some(body) = &context.body {
            content.push_str(body);
        }

        // Detect financial phishing
        let detections = self
            .analyzer
            .detect_financial_phishing(&content, &sender_domain);

        for (_institution, phishing_score, reason) in detections {
            score += phishing_score;
            evidence.push(format!("Financial phishing detected: {}", reason));
            confidence += 0.8; // High confidence in financial phishing detection
        }

        // Boost legitimate financial institutions
        if self.analyzer.is_financial_domain(&sender_domain) {
            if let Some(institution) = self.analyzer.get_institution_from_domain(&sender_domain) {
                score -= 15; // Boost legitimate financial institutions
                evidence.push(format!("Legitimate financial institution: {}", institution));
                confidence += 0.7;
            }
        }

        FeatureScore {
            feature_name: "Financial Validation".to_string(),
            score,
            confidence: confidence.min(1.0),
            evidence,
        }
    }

    fn name(&self) -> &str {
        "Financial Validation"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> FinancialValidationConfig {
        let mut institutions = HashMap::new();
        institutions.insert(
            "chase".to_string(),
            FinancialInstitution {
                domains: vec!["chase.com".to_string()],
                aliases: vec!["jp morgan".to_string()],
            },
        );

        FinancialValidationConfig {
            institutions,
            payment_processors: vec!["paypal".to_string()],
            phishing_keywords: vec!["account suspended".to_string()],
            urgency_keywords: vec!["urgent".to_string()],
            financial_terms: vec!["payment failed".to_string()],
        }
    }

    #[test]
    fn test_legitimate_financial_sender() {
        let analyzer = FinancialValidationAnalyzer::new(create_test_config());

        assert!(analyzer.validate_financial_sender("chase.com", "chase"));
        assert!(analyzer.validate_financial_sender("mail.chase.com", "chase"));
        assert!(!analyzer.validate_financial_sender("fake-chase.com", "chase"));
    }

    #[test]
    fn test_financial_phishing_detection() {
        let analyzer = FinancialValidationAnalyzer::new(create_test_config());

        let detections = analyzer.detect_financial_phishing(
            "Chase account suspended - urgent action required",
            "fake.com",
        );

        assert!(!detections.is_empty());
        assert!(detections[0].1 > 50); // Should have high score
    }

    #[test]
    fn test_institution_from_domain() {
        let analyzer = FinancialValidationAnalyzer::new(create_test_config());

        assert_eq!(
            analyzer.get_institution_from_domain("chase.com"),
            Some("chase".to_string())
        );
        assert_eq!(
            analyzer.get_institution_from_domain("mail.chase.com"),
            Some("chase".to_string())
        );
        assert_eq!(analyzer.get_institution_from_domain("fake.com"), None);
    }
}
