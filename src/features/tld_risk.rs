use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum TldRisk {
    Trusted,    // .gov, .edu, .mil - government/educational
    Standard,   // .com, .org, .net - standard commercial
    Regional,   // Country-specific TLDs with good reputation
    Suspicious, // TLDs commonly used for spam/phishing
    HighRisk,   // TLDs with very high abuse rates
}

#[derive(Debug, Clone, Deserialize)]
pub struct TldInfo {
    pub risk_level: TldRisk,
    pub abuse_score: i32,         // Base score adjustment for this TLD
    pub description: String,      // Description of the TLD
    pub common_uses: Vec<String>, // Common legitimate uses
}

#[derive(Debug, Clone, Deserialize)]
pub struct TldRiskConfig {
    pub tlds: HashMap<String, TldInfo>,
    pub default_risk: TldRisk,
    pub risk_multipliers: HashMap<String, f32>, // Context-based risk multipliers
}

#[derive(Debug, Clone)]
pub struct TldRiskAnalyzer {
    config: TldRiskConfig,
    tld_lookup: HashMap<String, TldInfo>,
}

impl TldRiskAnalyzer {
    pub fn new(config: TldRiskConfig) -> Self {
        let mut tld_lookup = HashMap::new();

        // Build lookup table
        for (tld, info) in &config.tlds {
            tld_lookup.insert(tld.to_lowercase(), info.clone());
        }

        Self { config, tld_lookup }
    }

    /// Extract TLD from domain
    pub fn extract_tld(&self, domain: &str) -> Option<String> {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            Some(parts.last()?.to_lowercase())
        } else {
            None
        }
    }

    /// Get TLD risk information
    pub fn get_tld_risk(&self, tld: &str) -> (TldRisk, i32, String) {
        let tld_lower = tld.to_lowercase();

        if let Some(info) = self.tld_lookup.get(&tld_lower) {
            (
                info.risk_level.clone(),
                info.abuse_score,
                info.description.clone(),
            )
        } else {
            // Unknown TLD - use default risk
            match self.config.default_risk {
                TldRisk::Trusted => (TldRisk::Trusted, -5, "Unknown trusted TLD".to_string()),
                TldRisk::Standard => (TldRisk::Standard, 0, "Unknown standard TLD".to_string()),
                TldRisk::Regional => (TldRisk::Regional, 5, "Unknown regional TLD".to_string()),
                TldRisk::Suspicious => (
                    TldRisk::Suspicious,
                    15,
                    "Unknown suspicious TLD".to_string(),
                ),
                TldRisk::HighRisk => (TldRisk::HighRisk, 30, "Unknown high-risk TLD".to_string()),
            }
        }
    }

    /// Analyze domain for TLD risk
    pub fn analyze_domain_risk(&self, domain: &str, content: &str) -> (i32, Vec<String>) {
        let mut score = 0;
        let mut evidence = Vec::new();

        if let Some(tld) = self.extract_tld(domain) {
            let (risk_level, base_score, description) = self.get_tld_risk(&tld);

            // Apply base score
            score += base_score;

            match risk_level {
                TldRisk::Trusted => {
                    evidence.push(format!("Trusted TLD: .{} ({})", tld, description));
                }
                TldRisk::Standard => {
                    evidence.push(format!("Standard TLD: .{} ({})", tld, description));
                }
                TldRisk::Regional => {
                    evidence.push(format!("Regional TLD: .{} ({})", tld, description));
                }
                TldRisk::Suspicious => {
                    evidence.push(format!("Suspicious TLD: .{} ({})", tld, description));

                    // Apply context-based multipliers for suspicious TLDs
                    score += self.calculate_context_risk(content, &tld);
                }
                TldRisk::HighRisk => {
                    evidence.push(format!("High-risk TLD: .{} ({})", tld, description));

                    // Apply higher context-based multipliers for high-risk TLDs
                    score += self.calculate_context_risk(content, &tld) * 2;
                }
            }
        } else {
            evidence.push("Invalid domain format".to_string());
            score += 10; // Penalty for invalid domain
        }

        (score, evidence)
    }

    /// Calculate additional risk based on content context
    fn calculate_context_risk(&self, content: &str, tld: &str) -> i32 {
        let content_lower = content.to_lowercase();
        let mut additional_score = 0;

        // Check for high-risk content patterns with suspicious TLDs
        let high_risk_patterns = [
            "health",
            "medical",
            "cure",
            "miracle",
            "supplement",
            "pharmacy",
            "viagra",
            "cialis",
            "weight loss",
            "bitcoin",
            "cryptocurrency",
            "investment",
            "trading",
            "lottery",
            "winner",
            "prize",
            "congratulations",
            "urgent",
            "immediate",
            "act now",
            "limited time",
            "verify account",
            "suspended",
            "click here",
        ];

        for pattern in &high_risk_patterns {
            if content_lower.contains(pattern) {
                additional_score += 10;
                break; // Only count once per email
            }
        }

        // Special handling for specific TLD + content combinations
        match tld {
            "tk" | "ml" | "ga" | "cf" => {
                // Free TLDs with any commercial content
                if content_lower.contains("buy")
                    || content_lower.contains("sale")
                    || content_lower.contains("discount")
                {
                    additional_score += 15;
                }
            }
            "shop" | "fun" | "site" => {
                // .shop/.fun/.site domains with health claims
                if content_lower.contains("health")
                    || content_lower.contains("cure")
                    || content_lower.contains("supplement")
                    || content_lower.contains("memory")
                    || content_lower.contains("cognitive")
                    || content_lower.contains("fungus")
                {
                    additional_score += 30;
                }
            }
            "icu" => {
                // .icu domains are often used for scams
                additional_score += 10;
            }
            _ => {}
        }

        additional_score
    }

    /// Extract domain from email address
    fn extract_domain(&self, email: &str) -> Option<String> {
        email.split('@').nth(1).map(|s| s.to_string())
    }
}

/// Feature extractor for TLD risk assessment
pub struct TldRiskFeature {
    analyzer: TldRiskAnalyzer,
}

impl Default for TldRiskFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl TldRiskFeature {
    pub fn new() -> Self {
        // Default configuration with common TLD risk levels
        let mut tlds = HashMap::new();

        // Trusted TLDs
        tlds.insert(
            "gov".to_string(),
            TldInfo {
                risk_level: TldRisk::Trusted,
                abuse_score: -10,
                description: "Government domain".to_string(),
                common_uses: vec!["Government agencies".to_string()],
            },
        );

        tlds.insert(
            "edu".to_string(),
            TldInfo {
                risk_level: TldRisk::Trusted,
                abuse_score: -10,
                description: "Educational institution".to_string(),
                common_uses: vec!["Universities, schools".to_string()],
            },
        );

        tlds.insert(
            "mil".to_string(),
            TldInfo {
                risk_level: TldRisk::Trusted,
                abuse_score: -10,
                description: "Military domain".to_string(),
                common_uses: vec!["Military organizations".to_string()],
            },
        );

        // Standard TLDs
        tlds.insert(
            "com".to_string(),
            TldInfo {
                risk_level: TldRisk::Standard,
                abuse_score: 0,
                description: "Commercial domain".to_string(),
                common_uses: vec!["Businesses, organizations".to_string()],
            },
        );

        tlds.insert(
            "org".to_string(),
            TldInfo {
                risk_level: TldRisk::Standard,
                abuse_score: 0,
                description: "Organization domain".to_string(),
                common_uses: vec!["Non-profits, organizations".to_string()],
            },
        );

        tlds.insert(
            "net".to_string(),
            TldInfo {
                risk_level: TldRisk::Standard,
                abuse_score: 0,
                description: "Network domain".to_string(),
                common_uses: vec!["Network providers, tech companies".to_string()],
            },
        );

        // Suspicious TLDs
        tlds.insert(
            "shop".to_string(),
            TldInfo {
                risk_level: TldRisk::Suspicious,
                abuse_score: 25,
                description: "Shopping domain - high spam abuse".to_string(),
                common_uses: vec!["E-commerce, often abused for spam".to_string()],
            },
        );

        tlds.insert(
            "fun".to_string(),
            TldInfo {
                risk_level: TldRisk::Suspicious,
                abuse_score: 30,
                description: "Fun domain - high spam abuse".to_string(),
                common_uses: vec!["Entertainment, often abused for spam".to_string()],
            },
        );

        tlds.insert(
            "site".to_string(),
            TldInfo {
                risk_level: TldRisk::Suspicious,
                abuse_score: 30,
                description: "Generic site domain - high spam abuse".to_string(),
                common_uses: vec!["Various, often abused for phishing".to_string()],
            },
        );

        tlds.insert(
            "icu".to_string(),
            TldInfo {
                risk_level: TldRisk::Suspicious,
                abuse_score: 30,
                description: "Generic domain - high abuse rate".to_string(),
                common_uses: vec!["Various, often abused".to_string()],
            },
        );

        tlds.insert(
            "digital".to_string(),
            TldInfo {
                risk_level: TldRisk::Suspicious,
                abuse_score: 25,
                description: "Digital domain - commonly abused for tech scams".to_string(),
                common_uses: vec!["Tech services, often abused for phishing".to_string()],
            },
        );

        tlds.insert(
            "lat".to_string(),
            TldInfo {
                risk_level: TldRisk::Suspicious,
                abuse_score: 25,
                description: "Latvia domain - commonly abused for international scams".to_string(),
                common_uses: vec!["Various, often abused for spam".to_string()],
            },
        );

        tlds.insert(
            "info".to_string(),
            TldInfo {
                risk_level: TldRisk::Suspicious,
                abuse_score: 30,
                description: "Info domain - heavily abused for spam".to_string(),
                common_uses: vec!["Information sites, heavily abused".to_string()],
            },
        );

        tlds.insert(
            "biz".to_string(),
            TldInfo {
                risk_level: TldRisk::Suspicious,
                abuse_score: 25,
                description: "Business domain - high spam rates".to_string(),
                common_uses: vec!["Business sites, often abused".to_string()],
            },
        );

        tlds.insert(
            "cc".to_string(),
            TldInfo {
                risk_level: TldRisk::Suspicious,
                abuse_score: 30,
                description: "Cocos Islands domain - frequently abused".to_string(),
                common_uses: vec!["Various, frequently abused".to_string()],
            },
        );

        tlds.insert(
            "ws".to_string(),
            TldInfo {
                risk_level: TldRisk::Suspicious,
                abuse_score: 25,
                description: "Western Samoa domain - popular with spammers".to_string(),
                common_uses: vec!["Various, popular with spammers".to_string()],
            },
        );

        tlds.insert(
            "tv".to_string(),
            TldInfo {
                risk_level: TldRisk::Suspicious,
                abuse_score: 20,
                description: "Tuvalu domain - often misused for spam".to_string(),
                common_uses: vec!["TV/media sites, often misused".to_string()],
            },
        );

        // High-risk TLDs
        tlds.insert(
            "tk".to_string(),
            TldInfo {
                risk_level: TldRisk::HighRisk,
                abuse_score: 40,
                description: "Free Tokelau domain - very high abuse".to_string(),
                common_uses: vec!["Free domains, heavily abused".to_string()],
            },
        );

        tlds.insert(
            "ml".to_string(),
            TldInfo {
                risk_level: TldRisk::HighRisk,
                abuse_score: 40,
                description: "Free Mali domain - very high abuse".to_string(),
                common_uses: vec!["Free domains, heavily abused".to_string()],
            },
        );

        tlds.insert(
            "ga".to_string(),
            TldInfo {
                risk_level: TldRisk::HighRisk,
                abuse_score: 40,
                description: "Free Gabon domain - very high abuse".to_string(),
                common_uses: vec!["Free domains, heavily abused".to_string()],
            },
        );

        tlds.insert(
            "cf".to_string(),
            TldInfo {
                risk_level: TldRisk::HighRisk,
                abuse_score: 40,
                description: "Free Central African Republic domain - very high abuse".to_string(),
                common_uses: vec!["Free domains, heavily abused".to_string()],
            },
        );

        let config = TldRiskConfig {
            tlds,
            default_risk: TldRisk::Standard,
            risk_multipliers: HashMap::new(),
        };

        Self {
            analyzer: TldRiskAnalyzer::new(config),
        }
    }

    pub fn from_config(config: TldRiskConfig) -> Self {
        Self {
            analyzer: TldRiskAnalyzer::new(config),
        }
    }
}

impl FeatureExtractor for TldRiskFeature {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();
        let mut confidence = 0.0f32;

        // Try multiple sources for domain information
        let sender_domain = self.get_primary_domain(context);

        log::info!("TLD Risk Assessment: sender_domain = '{}'", sender_domain);

        if sender_domain.is_empty() {
            log::warn!("TLD Risk Assessment: No valid domain found");
            return FeatureScore {
                feature_name: "TLD Risk Assessment".to_string(),
                score: 0,
                confidence: 0.0,
                evidence: vec!["No valid domain found in any header".to_string()],
            };
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

        // Analyze sender domain TLD risk
        let (domain_score, domain_evidence) =
            self.analyzer.analyze_domain_risk(&sender_domain, &content);
        score += domain_score;
        evidence.extend(domain_evidence);
        confidence += 0.8; // High confidence in TLD analysis

        // Also check Return-Path domain if different
        if let Some(return_path) = context.headers.get("return-path") {
            if let Some(return_domain) = self.analyzer.extract_domain(return_path) {
                if return_domain != sender_domain {
                    let (return_score, return_evidence) =
                        self.analyzer.analyze_domain_risk(&return_domain, &content);
                    if return_score > 0 {
                        score += return_score / 2; // Reduced weight for Return-Path
                        evidence.push(format!(
                            "Return-Path domain risk: {}",
                            return_evidence.join(", ")
                        ));
                        confidence += 0.6;
                    }
                }
            }
        }

        FeatureScore {
            feature_name: "TLD Risk Assessment".to_string(),
            score,
            confidence: confidence.min(1.0),
            evidence,
        }
    }

    fn name(&self) -> &str {
        "TLD Risk Assessment"
    }
}

impl TldRiskFeature {
    /// Get primary domain from multiple sources in order of preference
    fn get_primary_domain(&self, context: &MailContext) -> String {
        // 1. Try envelope sender first
        if let Some(sender) = &context.sender {
            if let Some(domain) = self.analyzer.extract_domain(sender) {
                return domain;
            }
        }

        // 2. Try From header (case-insensitive)
        if let Some(from) = context
            .headers
            .get("from")
            .or_else(|| context.headers.get("From"))
        {
            if let Some(domain) = self.analyzer.extract_domain(from) {
                return domain;
            }
        }

        // 3. Try context.from_header field
        if let Some(from) = &context.from_header {
            if let Some(domain) = self.analyzer.extract_domain(from) {
                return domain;
            }
        }

        // 4. Try Return-Path header (case-insensitive)
        if let Some(return_path) = context
            .headers
            .get("return-path")
            .or_else(|| context.headers.get("Return-Path"))
        {
            if let Some(domain) = self.analyzer.extract_domain(return_path) {
                return domain;
            }
        }

        // 5. Try Reply-To header (case-insensitive)
        if let Some(reply_to) = context
            .headers
            .get("reply-to")
            .or_else(|| context.headers.get("Reply-To"))
        {
            if let Some(domain) = self.analyzer.extract_domain(reply_to) {
                return domain;
            }
        }

        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> TldRiskConfig {
        let mut tlds = HashMap::new();
        tlds.insert(
            "com".to_string(),
            TldInfo {
                risk_level: TldRisk::Standard,
                abuse_score: 0,
                description: "Commercial".to_string(),
                common_uses: vec!["Business".to_string()],
            },
        );
        tlds.insert(
            "tk".to_string(),
            TldInfo {
                risk_level: TldRisk::HighRisk,
                abuse_score: 40,
                description: "High abuse".to_string(),
                common_uses: vec!["Free domains".to_string()],
            },
        );

        TldRiskConfig {
            tlds,
            default_risk: TldRisk::Standard,
            risk_multipliers: HashMap::new(),
        }
    }

    #[test]
    fn test_tld_extraction() {
        let analyzer = TldRiskAnalyzer::new(create_test_config());

        assert_eq!(analyzer.extract_tld("example.com"), Some("com".to_string()));
        assert_eq!(
            analyzer.extract_tld("sub.example.com"),
            Some("com".to_string())
        );
        assert_eq!(analyzer.extract_tld("invalid"), None);
    }

    #[test]
    fn test_tld_risk_assessment() {
        let analyzer = TldRiskAnalyzer::new(create_test_config());

        let (risk, score, _) = analyzer.get_tld_risk("com");
        assert_eq!(risk, TldRisk::Standard);
        assert_eq!(score, 0);

        let (risk, score, _) = analyzer.get_tld_risk("tk");
        assert_eq!(risk, TldRisk::HighRisk);
        assert_eq!(score, 40);
    }

    #[test]
    fn test_domain_risk_analysis() {
        let analyzer = TldRiskAnalyzer::new(create_test_config());

        let (score, evidence) = analyzer.analyze_domain_risk("example.com", "normal content");
        assert_eq!(score, 0);
        assert!(!evidence.is_empty());

        let (score, evidence) = analyzer.analyze_domain_risk("spam.tk", "urgent health cure");
        assert!(score > 40); // Base score + context risk
        assert!(!evidence.is_empty());
    }
}
