use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct EspProvider {
    pub domains: Vec<String>,
    pub reputation: EspReputation,
    pub aliases: Vec<String>, // Alternative names/subdomains
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum EspReputation {
    Trusted,    // High-reputation ESPs (SendGrid, Mailgun, etc.)
    Standard,   // Standard ESPs with good reputation
    Suspicious, // ESPs with mixed reputation
    Unknown,    // Unknown or new ESPs
}

#[derive(Debug, Clone, Deserialize)]
pub struct EspValidationConfig {
    pub providers: HashMap<String, EspProvider>,
    pub suspicious_patterns: Vec<String>, // Patterns that indicate ESP impersonation
    pub legitimate_senders: Vec<String>,  // Known legitimate senders using ESPs
}

#[derive(Debug, Clone)]
pub struct EspValidationAnalyzer {
    config: EspValidationConfig,
    esp_domains: HashMap<String, String>, // domain -> esp_name
    esp_reputation: HashMap<String, EspReputation>, // esp_name -> reputation
}

impl EspValidationAnalyzer {
    pub fn new(config: EspValidationConfig) -> Self {
        let mut esp_domains = HashMap::new();
        let mut esp_reputation = HashMap::new();

        // Build lookup tables
        for (esp_name, esp_provider) in &config.providers {
            // Map domains to ESP
            for domain in &esp_provider.domains {
                esp_domains.insert(domain.to_lowercase(), esp_name.clone());
            }

            // Map aliases to ESP
            for alias in &esp_provider.aliases {
                esp_domains.insert(alias.to_lowercase(), esp_name.clone());
            }

            // Store reputation
            esp_reputation.insert(esp_name.clone(), esp_provider.reputation.clone());
        }

        Self {
            config,
            esp_domains,
            esp_reputation,
        }
    }

    /// Check if domain is a known ESP
    pub fn is_esp_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Direct match
        if self.esp_domains.contains_key(&domain_lower) {
            return true;
        }

        // Check subdomains
        for esp_domain in self.esp_domains.keys() {
            if domain_lower.ends_with(&format!(".{}", esp_domain)) {
                return true;
            }
        }

        false
    }

    /// Get ESP name from domain
    pub fn get_esp_from_domain(&self, domain: &str) -> Option<String> {
        let domain_lower = domain.to_lowercase();

        // Direct lookup
        if let Some(esp) = self.esp_domains.get(&domain_lower) {
            return Some(esp.clone());
        }

        // Check subdomains
        for (esp_domain, esp_name) in &self.esp_domains {
            if domain_lower.ends_with(&format!(".{}", esp_domain)) {
                return Some(esp_name.clone());
            }
        }

        None
    }

    /// Get ESP reputation
    pub fn get_esp_reputation(&self, esp_name: &str) -> EspReputation {
        self.esp_reputation
            .get(esp_name)
            .cloned()
            .unwrap_or(EspReputation::Unknown)
    }

    /// Validate ESP usage - check for suspicious patterns
    pub fn validate_esp_usage(
        &self,
        sender_domain: &str,
        content: &str,
    ) -> Vec<(String, i32, String)> {
        let mut detections = Vec::new();
        let content_lower = content.to_lowercase();
        let sender_lower = sender_domain.to_lowercase();

        // Check if sender claims to be an ESP but isn't
        for esp_name in self.esp_domains.values() {
            if sender_lower.contains(&esp_name.to_lowercase()) && !self.is_esp_domain(&sender_lower)
            {
                // Suspicious domain mimicking ESP
                let score = 35;
                detections.push((
                    esp_name.clone(),
                    score,
                    format!(
                        "Suspicious domain mimicking ESP: {} in {}",
                        esp_name, sender_domain
                    ),
                ));
            }
        }

        // Check for suspicious patterns in content
        for pattern in &self.config.suspicious_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                let score = 20;
                detections.push((
                    "ESP Impersonation".to_string(),
                    score,
                    format!("Suspicious ESP-related pattern detected: {}", pattern),
                ));
            }
        }

        detections
    }

    /// Calculate ESP reputation score
    pub fn calculate_esp_score(&self, domain: &str) -> i32 {
        if let Some(esp_name) = self.get_esp_from_domain(domain) {
            match self.get_esp_reputation(&esp_name) {
                EspReputation::Trusted => -15,   // Strong boost for trusted ESPs
                EspReputation::Standard => -10,  // Moderate boost for standard ESPs
                EspReputation::Suspicious => 10, // Penalty for suspicious ESPs
                EspReputation::Unknown => 0,     // Neutral for unknown ESPs
            }
        } else {
            0 // Not an ESP
        }
    }

    /// Extract domain from email address
    fn extract_domain(&self, email: &str) -> Option<String> {
        email.split('@').nth(1).map(|s| s.to_string())
    }

    /// Check if sender is legitimate for ESP usage
    pub fn is_legitimate_esp_sender(&self, sender: &str) -> bool {
        let sender_lower = sender.to_lowercase();

        for legitimate in &self.config.legitimate_senders {
            if sender_lower.contains(&legitimate.to_lowercase()) {
                return true;
            }
        }

        false
    }
}

/// Feature extractor for ESP validation
pub struct EspValidationFeature {
    analyzer: EspValidationAnalyzer,
}

impl Default for EspValidationFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl EspValidationFeature {
    pub fn new() -> Self {
        // Default configuration with major ESPs
        let mut providers = HashMap::new();

        providers.insert(
            "sendgrid".to_string(),
            EspProvider {
                domains: vec!["sendgrid.net".to_string(), "sendgrid.com".to_string()],
                reputation: EspReputation::Trusted,
                aliases: vec!["sg.sendgrid.net".to_string()],
            },
        );

        providers.insert(
            "mailgun".to_string(),
            EspProvider {
                domains: vec!["mailgun.org".to_string(), "mailgun.com".to_string()],
                reputation: EspReputation::Trusted,
                aliases: vec!["mg.mailgun.org".to_string()],
            },
        );

        providers.insert(
            "mailchimp".to_string(),
            EspProvider {
                domains: vec!["mailchimp.com".to_string(), "mcsv.net".to_string()],
                reputation: EspReputation::Trusted,
                aliases: vec!["list-manage.com".to_string()],
            },
        );

        providers.insert(
            "amazonses".to_string(),
            EspProvider {
                domains: vec!["amazonses.com".to_string()],
                reputation: EspReputation::Trusted,
                aliases: vec!["ses.amazonaws.com".to_string()],
            },
        );

        providers.insert(
            "constantcontact".to_string(),
            EspProvider {
                domains: vec!["constantcontact.com".to_string()],
                reputation: EspReputation::Standard,
                aliases: vec!["ctctcdn.com".to_string()],
            },
        );

        providers.insert(
            "sparkpost".to_string(),
            EspProvider {
                domains: vec!["sparkpostmail.com".to_string(), "sparkpost.com".to_string()],
                reputation: EspReputation::Standard,
                aliases: vec!["spmailtechno.com".to_string()],
            },
        );

        providers.insert(
            "campaignmonitor".to_string(),
            EspProvider {
                domains: vec!["campaignmonitor.com".to_string()],
                reputation: EspReputation::Standard,
                aliases: vec!["createsend.com".to_string()],
            },
        );

        providers.insert(
            "adobe_campaign".to_string(),
            EspProvider {
                domains: vec!["cjm.adobe.com".to_string()],
                reputation: EspReputation::Trusted,
                aliases: vec!["cname.cjm.adobe.com".to_string()],
            },
        );

        let config = EspValidationConfig {
            providers,
            suspicious_patterns: vec![
                "email service provider".to_string(),
                "bulk email service".to_string(),
                "mass email sender".to_string(),
                "email delivery service".to_string(),
            ],
            legitimate_senders: vec![
                "noreply".to_string(),
                "no-reply".to_string(),
                "notifications".to_string(),
                "alerts".to_string(),
                "updates".to_string(),
            ],
        };

        Self {
            analyzer: EspValidationAnalyzer::new(config),
        }
    }

    pub fn from_config(config: EspValidationConfig) -> Self {
        Self {
            analyzer: EspValidationAnalyzer::new(config),
        }
    }
}

impl FeatureExtractor for EspValidationFeature {
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
                    feature_name: "ESP Validation".to_string(),
                    score: 0,
                    confidence: 0.0,
                    evidence: vec!["No valid sender domain found".to_string()],
                };
            }
        } else {
            return FeatureScore {
                feature_name: "ESP Validation".to_string(),
                score: 0,
                confidence: 0.0,
                evidence: vec!["No sender found".to_string()],
            };
        };

        // Check if sender is an ESP
        if self.analyzer.is_esp_domain(&sender_domain) {
            if let Some(esp_name) = self.analyzer.get_esp_from_domain(&sender_domain) {
                let esp_score = self.analyzer.calculate_esp_score(&sender_domain);
                score += esp_score;

                let reputation = self.analyzer.get_esp_reputation(&esp_name);
                match reputation {
                    EspReputation::Trusted => {
                        evidence.push(format!("Trusted ESP: {}", esp_name));
                        confidence += 0.9;
                    }
                    EspReputation::Standard => {
                        evidence.push(format!("Standard ESP: {}", esp_name));
                        confidence += 0.7;
                    }
                    EspReputation::Suspicious => {
                        evidence.push(format!("Suspicious ESP: {}", esp_name));
                        confidence += 0.8;
                    }
                    EspReputation::Unknown => {
                        evidence.push(format!("Unknown ESP: {}", esp_name));
                        confidence += 0.5;
                    }
                }
            }
        }

        // Combine subject and body for content analysis
        let mut content = String::new();
        if let Some(subject) = context.headers.get("subject") {
            content.push_str(subject);
            content.push(' ');
        }
        if let Some(body) = &context.body {
            content.push_str(body);
        }

        // Validate ESP usage
        let detections = self.analyzer.validate_esp_usage(&sender_domain, &content);

        for (_esp, esp_score, reason) in detections {
            score += esp_score;
            evidence.push(format!("ESP validation issue: {}", reason));
            confidence += 0.6;
        }

        FeatureScore {
            feature_name: "ESP Validation".to_string(),
            score,
            confidence: confidence.min(1.0),
            evidence,
        }
    }

    fn name(&self) -> &str {
        "ESP Validation"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> EspValidationConfig {
        let mut providers = HashMap::new();
        providers.insert(
            "sendgrid".to_string(),
            EspProvider {
                domains: vec!["sendgrid.net".to_string()],
                reputation: EspReputation::Trusted,
                aliases: vec![],
            },
        );

        EspValidationConfig {
            providers,
            suspicious_patterns: vec!["bulk email service".to_string()],
            legitimate_senders: vec!["noreply".to_string()],
        }
    }

    #[test]
    fn test_esp_domain_detection() {
        let analyzer = EspValidationAnalyzer::new(create_test_config());

        assert!(analyzer.is_esp_domain("sendgrid.net"));
        assert!(analyzer.is_esp_domain("bounce.sendgrid.net"));
        assert!(!analyzer.is_esp_domain("fake-sendgrid.com"));
    }

    #[test]
    fn test_esp_reputation() {
        let analyzer = EspValidationAnalyzer::new(create_test_config());

        assert_eq!(
            analyzer.get_esp_reputation("sendgrid"),
            EspReputation::Trusted
        );
        assert_eq!(
            analyzer.get_esp_reputation("unknown"),
            EspReputation::Unknown
        );
    }

    #[test]
    fn test_esp_score_calculation() {
        let analyzer = EspValidationAnalyzer::new(create_test_config());

        assert_eq!(analyzer.calculate_esp_score("sendgrid.net"), -15); // Trusted ESP
        assert_eq!(analyzer.calculate_esp_score("unknown.com"), 0); // Not an ESP
    }
}
