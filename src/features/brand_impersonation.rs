use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use regex::Regex;
use std::collections::HashMap;

pub struct BrandImpersonationFeature {
    brand_patterns: HashMap<String, Vec<String>>,
    legitimate_domains: HashMap<String, Vec<String>>,
}

impl Default for BrandImpersonationFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl BrandImpersonationFeature {
    pub fn new() -> Self {
        let mut brand_patterns = HashMap::new();
        let mut legitimate_domains = HashMap::new();

        // Major brands and their legitimate domains
        brand_patterns.insert(
            "starbucks".to_string(),
            vec![
                r"(?i)\bstarbucks\b".to_string(),
                r"(?i)\bstarbuck\b".to_string(),
            ],
        );
        legitimate_domains.insert(
            "starbucks".to_string(),
            vec!["starbucks.com".to_string(), "starbucks.co.uk".to_string()],
        );

        brand_patterns.insert(
            "omaha_steaks".to_string(),
            vec![
                r"(?i)\bomaha\s*steaks?\b".to_string(),
                r"(?i)\bomaha\b".to_string(),
            ],
        );
        legitimate_domains.insert(
            "omaha_steaks".to_string(),
            vec!["omahasteaks.com".to_string()],
        );

        brand_patterns.insert("amazon".to_string(), vec![r"(?i)\bamazon\b".to_string()]);
        legitimate_domains.insert(
            "amazon".to_string(),
            vec!["amazon.com".to_string(), "amazon.co.uk".to_string()],
        );

        brand_patterns.insert(
            "harbor_freight".to_string(),
            vec![r"(?i)\bharbor\s*freight\b".to_string()],
        );
        legitimate_domains.insert(
            "harbor_freight".to_string(),
            vec!["harborfreight.com".to_string()],
        );

        brand_patterns.insert(
            "home_depot".to_string(),
            vec![r"(?i)\bhome\s*depot\b".to_string()],
        );
        legitimate_domains.insert("home_depot".to_string(), vec!["homedepot.com".to_string()]);

        brand_patterns.insert("lowes".to_string(), vec![r"(?i)\blowe'?s\b".to_string()]);
        legitimate_domains.insert("lowes".to_string(), vec!["lowes.com".to_string()]);

        brand_patterns.insert(
            "tinnitus".to_string(),
            vec![
                r"(?i)\btinnitus\s*\d+\b".to_string(),
                r"(?i)\bhearing\s*(aid|device)\b".to_string(),
            ],
        );
        legitimate_domains.insert("tinnitus".to_string(), vec!["hearingaid.com".to_string()]);
        legitimate_domains.insert("paypal".to_string(), vec!["paypal.com".to_string()]);

        Self {
            brand_patterns,
            legitimate_domains,
        }
    }

    fn extract_domain(&self, email: &str) -> Option<String> {
        email.split('@').nth(1).map(|s| s.to_lowercase())
    }

    fn is_suspicious_domain_pattern(&self, domain: &str) -> bool {
        // Random-looking domain patterns
        let patterns = [
            r"^[bcdfghjklmnpqrstvwxyz]{3,}[aeiou][bcdfghjklmnpqrstvwxyz]{3,}\.(com|org|net|co\.uk|cc)$",
            r"^[a-z]{8,15}\.(cc|tk|ml|ga|cf)$",
            // Dictionary word + random suffix patterns
            r"^[a-z]{4,8}(watch|stone|car|dock|temp)\.(org|com|net)$",
            // Random word combinations
            r"^(mud|oil|top|big|new|old)(watch|stone|car|dock|temp|cause)\.(org|com|net)$",
        ];

        for pattern in &patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(domain) {
                    return true;
                }
            }
        }
        false
    }

    fn detect_brand_mentions(&self, text: &str) -> Vec<String> {
        let mut detected_brands = Vec::new();
        let text_lower = text.to_lowercase();

        for (brand, patterns) in &self.brand_patterns {
            for pattern in patterns {
                if let Ok(regex) = Regex::new(pattern) {
                    if regex.is_match(&text_lower) {
                        detected_brands.push(brand.clone());
                        break;
                    }
                }
            }
        }

        // Also do simple string matching as fallback
        if text_lower.contains("starbucks") {
            detected_brands.push("starbucks".to_string());
        }
        if text_lower.contains("omaha") {
            detected_brands.push("omaha_steaks".to_string());
        }
        if text_lower.contains("harbor freight") {
            detected_brands.push("harbor_freight".to_string());
        }
        if text_lower.contains("home depot") {
            detected_brands.push("home_depot".to_string());
        }
        if text_lower.contains("lowes") || text_lower.contains("lowe's") {
            detected_brands.push("lowes".to_string());
        }
        if text_lower.contains("tinnitus") {
            detected_brands.push("tinnitus".to_string());
        }

        detected_brands
    }

    fn is_legitimate_domain_for_brand(&self, brand: &str, domain: &str) -> bool {
        if let Some(legitimate) = self.legitimate_domains.get(brand) {
            return legitimate
                .iter()
                .any(|d| domain == d || domain.ends_with(&format!(".{}", d)));
        }
        false
    }
}

impl FeatureExtractor for BrandImpersonationFeature {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();
        let mut confidence: f32 = 0.0;

        // Get sender domain
        let sender_domain = if let Some(sender) = &context.sender {
            self.extract_domain(sender)
        } else {
            None
        };

        // Analyze subject and body for brand mentions
        let subject = context.subject.as_deref().unwrap_or("");
        let body = context.body.as_deref().unwrap_or("");

        // Decode subject if it's still encoded - simple Q-encoding decoder
        let decoded_subject = if subject.contains("=?UTF-8?Q?") || subject.contains("=?ASCII?Q?") {
            decode_q_encoding(subject)
        } else {
            subject.to_string()
        };

        let combined_text = format!("{} {}", decoded_subject, body);

        let detected_brands = self.detect_brand_mentions(&combined_text);

        if let Some(domain) = &sender_domain {
            // Check for suspicious domain patterns
            if self.is_suspicious_domain_pattern(domain) {
                score += 30;
                evidence.push(format!("Suspicious domain pattern: {}", domain));
                confidence += 0.7;
            }

            // Check for brand impersonation
            for brand in &detected_brands {
                if !self.is_legitimate_domain_for_brand(brand, domain) {
                    score += 85;
                    evidence.push(format!(
                        "Brand impersonation: Claims to be {} but sender domain is {}",
                        brand, domain
                    ));
                    confidence += 0.9;
                }
            }

            // Additional penalties for suspicious patterns with brand claims
            if !detected_brands.is_empty() {
                // .org domains with commercial brand claims are suspicious
                if domain.ends_with(".org") {
                    score += 25;
                    evidence.push(format!(
                        "Commercial brand claims from .org domain: {}",
                        domain
                    ));
                    confidence += 0.7;
                }

                // Suspicious TLD penalty
                if domain.ends_with(".cc")
                    || domain.ends_with(".tk")
                    || domain.ends_with(".ml")
                    || domain.ends_with(".co.uk")
                {
                    score += 35;
                    evidence.push(format!("Suspicious TLD with brand claims: {}", domain));
                    confidence += 0.6;
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

/// Simple Q-encoding decoder for MIME headers
fn decode_q_encoding(encoded: &str) -> String {
    // Extract the encoded part between =?charset?Q? and ?=
    if let Some(start) = encoded.find("?Q?") {
        if let Some(end) = encoded.rfind("?=") {
            let encoded_part = &encoded[start + 3..end];

            // Decode Q-encoding: =XX becomes the byte XX, _ becomes space
            let mut result = String::new();
            let mut chars = encoded_part.chars().peekable();

            while let Some(ch) = chars.next() {
                match ch {
                    '=' => {
                        // Read next two hex digits
                        if let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
                            if let Ok(byte) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) {
                                result.push(byte as char);
                            }
                        }
                    }
                    '_' => result.push(' '),
                    other => result.push(other),
                }
            }

            return result;
        }
    }

    encoded.to_string()
}
