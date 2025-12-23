use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct BrandConfig {
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrandImpersonationConfig {
    pub brands: HashMap<String, BrandConfig>,
    pub security_keywords: Vec<String>,
    pub financial_keywords: Vec<String>,
    pub urgency_keywords: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BrandImpersonationAnalyzer {
    config: BrandImpersonationConfig,
    brand_domains: HashMap<String, Vec<String>>, // brand_name -> domains
    domain_to_brand: HashMap<String, String>,    // domain -> brand_name
}

impl BrandImpersonationAnalyzer {
    pub fn new(config: BrandImpersonationConfig) -> Self {
        let mut brand_domains = HashMap::new();
        let mut domain_to_brand = HashMap::new();

        // Build lookup tables
        for (brand_name, brand_config) in &config.brands {
            let domains: Vec<String> = brand_config
                .domains
                .iter()
                .map(|d| d.to_lowercase())
                .collect();

            for domain in &domains {
                domain_to_brand.insert(domain.clone(), brand_name.clone());
            }

            brand_domains.insert(brand_name.clone(), domains);
        }

        Self {
            config,
            brand_domains,
            domain_to_brand,
        }
    }

    /// Check if sender domain is legitimate for claimed brand
    pub fn validate_brand_sender(&self, sender_domain: &str, claimed_brand: &str) -> bool {
        let sender_lower = sender_domain.to_lowercase();
        let brand_lower = claimed_brand.to_lowercase();

        // Get legitimate domains for this brand
        if let Some(legitimate_domains) = self.brand_domains.get(&brand_lower) {
            // Check direct domain match
            if legitimate_domains.contains(&sender_lower) {
                return true;
            }

            // Check subdomain match
            for domain in legitimate_domains {
                if sender_lower.ends_with(&format!(".{}", domain)) {
                    return true;
                }
            }
        }

        false
    }

    /// Detect brand impersonation in content
    pub fn detect_brand_impersonation(
        &self,
        content: &str,
        sender_domain: &str,
    ) -> Vec<(String, i32, String)> {
        let mut detections = Vec::new();
        let sender_lower = sender_domain.to_lowercase();

        // Only check for impersonation if sender domain contains brand name
        // This prevents flagging legitimate mentions of brands in content
        for brand_name in self.brand_domains.keys() {
            let brand_lower = brand_name.to_lowercase();

            // Check if sender domain contains the brand name (potential impersonation)
            if sender_lower.contains(&brand_lower)
                && !self.validate_brand_sender(&sender_lower, &brand_lower)
            {
                // This is a suspicious domain mimicking the brand
                let score = 40 + self.calculate_context_score(content, &brand_lower);
                detections.push((
                    brand_name.clone(),
                    score,
                    format!(
                        "Suspicious domain mimicking brand: {} in {}",
                        brand_name, sender_domain
                    ),
                ));
            }
        }

        detections
    }

    /// Calculate additional score based on suspicious context
    fn calculate_context_score(&self, content: &str, _brand: &str) -> i32 {
        let content_lower = content.to_lowercase();
        let mut score = 0;

        // Check for security-related impersonation
        for keyword in &self.config.security_keywords {
            if content_lower.contains(&keyword.to_lowercase()) {
                score += 30;
                break;
            }
        }

        // Check for financial-related impersonation
        for keyword in &self.config.financial_keywords {
            if content_lower.contains(&keyword.to_lowercase()) {
                score += 25;
                break;
            }
        }

        // Check for urgency tactics
        for keyword in &self.config.urgency_keywords {
            if content_lower.contains(&keyword.to_lowercase()) {
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

    /// Get brand from domain if it's a known legitimate domain
    pub fn get_brand_from_domain(&self, domain: &str) -> Option<String> {
        let domain_lower = domain.to_lowercase();

        // Direct lookup
        if let Some(brand) = self.domain_to_brand.get(&domain_lower) {
            return Some(brand.clone());
        }

        // Check subdomains
        for (legitimate_domain, brand) in &self.domain_to_brand {
            if domain_lower.ends_with(&format!(".{}", legitimate_domain)) {
                return Some(brand.clone());
            }
        }

        None
    }
}

/// Feature extractor for brand impersonation detection
pub struct BrandImpersonationFeature {
    analyzer: BrandImpersonationAnalyzer,
}

impl Default for BrandImpersonationFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl BrandImpersonationFeature {
    pub fn new() -> Self {
        // Default configuration with major brands
        let mut brands = HashMap::new();

        brands.insert(
            "microsoft".to_string(),
            BrandConfig {
                domains: vec![
                    "microsoft.com".to_string(),
                    "outlook.com".to_string(),
                    "live.com".to_string(),
                ],
            },
        );

        brands.insert(
            "apple".to_string(),
            BrandConfig {
                domains: vec!["apple.com".to_string(), "icloud.com".to_string()],
            },
        );

        brands.insert(
            "google".to_string(),
            BrandConfig {
                domains: vec!["google.com".to_string(), "gmail.com".to_string()],
            },
        );

        brands.insert(
            "amazon".to_string(),
            BrandConfig {
                domains: vec!["amazon.com".to_string(), "amazonses.com".to_string()],
            },
        );

        brands.insert(
            "paypal".to_string(),
            BrandConfig {
                domains: vec![
                    "paypal.com".to_string(),
                    "paypal-communications.com".to_string(),
                ],
            },
        );

        brands.insert(
            "chase".to_string(),
            BrandConfig {
                domains: vec!["chase.com".to_string(), "jpmorgan.com".to_string()],
            },
        );

        let config = BrandImpersonationConfig {
            brands,
            security_keywords: vec![
                "security alert".to_string(),
                "suspicious login".to_string(),
                "unauthorized access".to_string(),
                "breach detected".to_string(),
                "virus found".to_string(),
                "malware detected".to_string(),
                "security scan required".to_string(),
                "update antivirus".to_string(),
            ],
            financial_keywords: vec![
                "update payment method".to_string(),
                "verify card information".to_string(),
                "confirm bank details".to_string(),
                "resolve payment issue".to_string(),
                "account suspended".to_string(),
                "payment failed".to_string(),
                "billing problem".to_string(),
            ],
            urgency_keywords: vec![
                "immediate action".to_string(),
                "urgent".to_string(),
                "expires today".to_string(),
                "act now".to_string(),
                "limited time".to_string(),
                "verify now".to_string(),
                "click here now".to_string(),
            ],
        };

        Self {
            analyzer: BrandImpersonationAnalyzer::new(config),
        }
    }

    pub fn from_config(config: BrandImpersonationConfig) -> Self {
        Self {
            analyzer: BrandImpersonationAnalyzer::new(config),
        }
    }
}

impl FeatureExtractor for BrandImpersonationFeature {
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
                    feature_name: "Brand Impersonation".to_string(),
                    score: 0,
                    confidence: 0.0,
                    evidence: vec!["No valid sender domain found".to_string()],
                };
            }
        } else {
            return FeatureScore {
                feature_name: "Brand Impersonation".to_string(),
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
            if !body.is_empty() {
                content.push_str(body);
            }
        }

        // Detect brand impersonation
        let detections = self
            .analyzer
            .detect_brand_impersonation(&content, &sender_domain);

        for (_brand, brand_score, reason) in detections {
            score += brand_score;
            evidence.push(format!("Brand impersonation detected: {}", reason));
            confidence += 0.7; // High confidence in brand impersonation detection
        }

        // Check if sender claims to be from a major brand but isn't
        let sender_brand = self.analyzer.get_brand_from_domain(&sender_domain);
        if sender_brand.is_none() {
            // Check for brand keywords in sender domain itself
            for brand_name in self.analyzer.brand_domains.keys() {
                if sender_domain
                    .to_lowercase()
                    .contains(&brand_name.to_lowercase())
                {
                    score += 40;
                    evidence.push(format!(
                        "Suspicious domain mimicking brand: {} in {}",
                        brand_name, sender_domain
                    ));
                    confidence += 0.8;
                    break;
                }
            }
        }

        FeatureScore {
            feature_name: "Brand Impersonation".to_string(),
            score,
            confidence: confidence.min(1.0),
            evidence,
        }
    }

    fn name(&self) -> &str {
        "Brand Impersonation"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> BrandImpersonationConfig {
        let mut brands = HashMap::new();
        brands.insert(
            "microsoft".to_string(),
            BrandConfig {
                domains: vec!["microsoft.com".to_string(), "outlook.com".to_string()],
            },
        );
        brands.insert(
            "paypal".to_string(),
            BrandConfig {
                domains: vec!["paypal.com".to_string()],
            },
        );

        BrandImpersonationConfig {
            brands,
            security_keywords: vec!["security alert".to_string()],
            financial_keywords: vec!["payment failed".to_string()],
            urgency_keywords: vec!["urgent".to_string()],
        }
    }

    #[test]
    fn test_legitimate_brand_sender() {
        let analyzer = BrandImpersonationAnalyzer::new(create_test_config());

        assert!(analyzer.validate_brand_sender("microsoft.com", "microsoft"));
        assert!(analyzer.validate_brand_sender("mail.microsoft.com", "microsoft"));
        assert!(!analyzer.validate_brand_sender("fake-microsoft.com", "microsoft"));
    }

    #[test]
    fn test_brand_impersonation_detection() {
        let analyzer = BrandImpersonationAnalyzer::new(create_test_config());

        let detections = analyzer.detect_brand_impersonation(
            "Microsoft security alert: urgent action required",
            "fake.com",
        );

        assert!(!detections.is_empty());
        assert!(detections[0].1 > 50); // Should have high score due to security + urgency
    }

    #[test]
    fn test_brand_from_domain() {
        let analyzer = BrandImpersonationAnalyzer::new(create_test_config());

        assert_eq!(
            analyzer.get_brand_from_domain("microsoft.com"),
            Some("microsoft".to_string())
        );
        assert_eq!(
            analyzer.get_brand_from_domain("mail.microsoft.com"),
            Some("microsoft".to_string())
        );
        assert_eq!(analyzer.get_brand_from_domain("fake.com"), None);
    }
}
