use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use std::collections::HashMap;

pub struct GeographicMismatchFeature {
    tld_countries: HashMap<String, String>,
}

impl Default for GeographicMismatchFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl GeographicMismatchFeature {
    pub fn new() -> Self {
        let mut tld_countries = HashMap::new();

        // Major country TLDs
        tld_countries.insert("cn".to_string(), "chinese".to_string());
        tld_countries.insert("jp".to_string(), "japanese".to_string());
        tld_countries.insert("kr".to_string(), "korean".to_string());
        tld_countries.insert("ru".to_string(), "russian".to_string());
        tld_countries.insert("de".to_string(), "german".to_string());
        tld_countries.insert("fr".to_string(), "french".to_string());
        tld_countries.insert("it".to_string(), "italian".to_string());
        tld_countries.insert("es".to_string(), "spanish".to_string());
        tld_countries.insert("br".to_string(), "portuguese".to_string());
        tld_countries.insert("in".to_string(), "hindi".to_string());

        Self { tld_countries }
    }

    fn extract_tld(&self, domain: &str) -> Option<String> {
        domain.split('.').next_back().map(|s| s.to_lowercase())
    }

    fn detect_content_language(&self, text: &str) -> Option<String> {
        let text_lower = text.to_lowercase();

        // Japanese detection (Hiragana, Katakana, common Japanese words)
        if text.chars().any(|c| {
            ('\u{3040}'..='\u{309F}').contains(&c) || ('\u{30A0}'..='\u{30FF}').contains(&c)
        }) || text_lower.contains("ポイント")
            || text_lower.contains("残高")
            || text_lower.contains("ご案内")
            || text_lower.contains("jaccs") && text.chars().any(|c| c as u32 > 127)
        {
            return Some("japanese".to_string());
        }

        // Chinese detection (CJK ideographs, common Chinese words)
        if text.chars().any(|c| ('\u{4E00}'..='\u{9FFF}').contains(&c))
            && !text.chars().any(|c| ('\u{3040}'..='\u{309F}').contains(&c))
        {
            return Some("chinese".to_string());
        }

        // Korean detection (Hangul)
        if text.chars().any(|c| ('\u{AC00}'..='\u{D7AF}').contains(&c)) {
            return Some("korean".to_string());
        }

        // Russian detection (Cyrillic)
        if text.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c)) {
            return Some("russian".to_string());
        }

        None
    }
}

impl FeatureExtractor for GeographicMismatchFeature {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();

        // Get sender domain
        let sender_domain = if let Some(sender) = &context.sender {
            sender.split('@').nth(1).unwrap_or("").to_lowercase()
        } else {
            return FeatureScore {
                feature_name: "Geographic Mismatch".to_string(),
                score: 0,
                confidence: 0.0,
                evidence: vec!["No sender domain found".to_string()],
            };
        };

        // Extract TLD
        let tld = match self.extract_tld(&sender_domain) {
            Some(tld) => tld,
            None => {
                return FeatureScore {
                    feature_name: "Geographic Mismatch".to_string(),
                    score: 0,
                    confidence: 0.0,
                    evidence: vec!["Could not extract TLD".to_string()],
                }
            }
        };

        // Check if TLD has country association
        let expected_language = match self.tld_countries.get(&tld) {
            Some(lang) => lang,
            None => {
                return FeatureScore {
                    feature_name: "Geographic Mismatch".to_string(),
                    score: 0,
                    confidence: 0.0,
                    evidence: vec![format!("TLD .{} not in country mapping", tld)],
                }
            }
        };

        // Analyze content language
        let combined_text = format!(
            "{} {} {}",
            context.subject.as_deref().unwrap_or(""),
            context.body.as_deref().unwrap_or(""),
            context.from_header.as_deref().unwrap_or("")
        );

        if let Some(detected_language) = self.detect_content_language(&combined_text) {
            if detected_language != *expected_language {
                score += 75;
                evidence.push(format!(
                    "Geographic mismatch: .{} domain (expects {}) but content is {}",
                    tld, expected_language, detected_language
                ));

                // Extra penalty for high-abuse combinations
                if tld == "cn" && detected_language == "japanese" {
                    score += 25;
                    evidence.push("High-risk pattern: Chinese domain with Japanese content (common in phishing)".to_string());
                }
            }
        }

        let confidence = if score > 0 { 0.9 } else { 0.0 };

        FeatureScore {
            feature_name: "Geographic Mismatch".to_string(),
            score,
            confidence,
            evidence,
        }
    }

    fn name(&self) -> &str {
        "geographic_mismatch"
    }
}
