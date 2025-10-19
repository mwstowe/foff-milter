use super::DetectionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AdultContentConfig {
    pub adult_services: AdultServices,
    pub romance_fraud: RomanceFraud,
    pub content_filtering: ContentFiltering,
    pub sender_patterns: SenderPatterns,
    pub legitimate_exclusions: LegitimateExclusions,
    pub confidence_scoring: ConfidenceScoring,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AdultServices {
    pub dating_scams: Vec<String>,
    pub adult_products: Vec<String>,
    pub explicit_content: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RomanceFraud {
    pub emotional_manipulation: Vec<String>,
    pub financial_requests: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ContentFiltering {
    pub suggestive_terms: Vec<String>,
    pub body_parts: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SenderPatterns {
    pub suspicious_usernames: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LegitimateExclusions {
    pub medical_organizations: Vec<String>,
    pub health_services: Vec<String>,
    pub news_organizations: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConfidenceScoring {
    pub explicit_content: u32,
    pub adult_products: u32,
    pub dating_scams: u32,
    pub romance_fraud: u32,
    pub suggestive_content: u32,
    pub suspicious_usernames: u32,
}

pub struct AdultContentDetector {
    config: AdultContentConfig,
}

impl AdultContentDetector {
    pub fn new(config: AdultContentConfig) -> Self {
        Self { config }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: AdultContentConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn check_adult_content(&self, subject: &str, body: &str, sender: &str, sender_domain: &str) -> DetectionResult {
        // Check if sender is from legitimate organization
        if self.is_legitimate_sender(sender_domain) {
            return DetectionResult::no_match("AdultContent".to_string());
        }

        let mut confidence = 0;
        let mut reasons = Vec::new();
        let combined_text = format!("{} {}", subject, body).to_lowercase();

        // Check explicit content (highest priority)
        if self.check_patterns(&combined_text, &self.config.adult_services.explicit_content) {
            confidence += self.config.confidence_scoring.explicit_content;
            reasons.push("Explicit content detected".to_string());
        }

        // Check romance fraud patterns
        let has_emotional = self.check_patterns(&combined_text, &self.config.romance_fraud.emotional_manipulation);
        let has_financial = self.check_patterns(&combined_text, &self.config.romance_fraud.financial_requests);
        if has_emotional && has_financial {
            confidence += self.config.confidence_scoring.romance_fraud;
            reasons.push("Romance fraud patterns detected".to_string());
        }

        // Check adult products
        if self.check_patterns(&combined_text, &self.config.adult_services.adult_products) {
            confidence += self.config.confidence_scoring.adult_products;
            reasons.push("Adult product spam detected".to_string());
        }

        // Check dating scams
        if self.check_patterns(&combined_text, &self.config.adult_services.dating_scams) {
            confidence += self.config.confidence_scoring.dating_scams;
            reasons.push("Dating scam patterns detected".to_string());
        }

        // Check suggestive content
        if self.check_patterns(&combined_text, &self.config.content_filtering.suggestive_terms) ||
           self.check_patterns(&combined_text, &self.config.content_filtering.body_parts) {
            confidence += self.config.confidence_scoring.suggestive_content;
            reasons.push("Suggestive content detected".to_string());
        }

        // Check suspicious usernames
        if self.check_username_patterns(sender) {
            confidence += self.config.confidence_scoring.suspicious_usernames;
            reasons.push("Suspicious username pattern detected".to_string());
        }

        let matched = confidence > 0;
        let reason = if reasons.is_empty() {
            "No adult content indicators".to_string()
        } else {
            reasons.join(", ")
        };

        DetectionResult::new(matched, confidence, reason, "AdultContent".to_string())
    }

    fn check_patterns(&self, text: &str, patterns: &[String]) -> bool {
        patterns.iter().any(|pattern| text.contains(pattern))
    }

    fn check_username_patterns(&self, sender: &str) -> bool {
        let sender_lower = sender.to_lowercase();
        self.config.sender_patterns.suspicious_usernames
            .iter()
            .any(|pattern| {
                // Simple pattern matching for usernames
                if pattern.starts_with(".*") && pattern.ends_with(".*") {
                    let core = &pattern[2..pattern.len()-2];
                    sender_lower.contains(core)
                } else {
                    sender_lower.contains(pattern)
                }
            })
    }

    fn is_legitimate_sender(&self, domain: &str) -> bool {
        let all_legitimate = [
            &self.config.legitimate_exclusions.medical_organizations,
            &self.config.legitimate_exclusions.health_services,
            &self.config.legitimate_exclusions.news_organizations,
        ];

        for legitimate_list in all_legitimate.iter() {
            for legitimate_domain in legitimate_list.iter() {
                if domain.ends_with(legitimate_domain) {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_all_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        patterns.extend(self.config.adult_services.dating_scams.clone());
        patterns.extend(self.config.adult_services.adult_products.clone());
        patterns.extend(self.config.adult_services.explicit_content.clone());
        patterns.extend(self.config.romance_fraud.emotional_manipulation.clone());
        patterns.extend(self.config.romance_fraud.financial_requests.clone());
        patterns.extend(self.config.content_filtering.suggestive_terms.clone());
        patterns.extend(self.config.content_filtering.body_parts.clone());
        patterns.sort();
        patterns.dedup();
        patterns
    }
}
