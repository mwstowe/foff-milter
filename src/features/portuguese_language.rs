use super::{FeatureExtractor, FeatureScore};
use crate::language::LanguageDetector;
use crate::MailContext;

pub struct PortugueseLanguageAnalyzer;

impl Default for PortugueseLanguageAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PortugueseLanguageAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl FeatureExtractor for PortugueseLanguageAnalyzer {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();

        let subject = context.subject.as_deref().unwrap_or("");
        let body = context.body.as_deref().unwrap_or("");
        let combined_text = format!("{} {}", subject, body);

        // Check for Portuguese language
        if LanguageDetector::contains_portuguese(&combined_text) {
            // Skip Portuguese detection for legitimate retail domains
            let sender_domain = context
                .from_header
                .as_deref()
                .and_then(|from| from.split('@').nth(1))
                .unwrap_or("")
                .to_lowercase();

            let legitimate_retail_domains = [
                "torrid.com",
                "mktg.torrid.com",
                "levi.com",
                "mail.levi.com",
                "target.com",
                "walmart.com",
                "amazon.com",
                "bestbuy.com",
                "homedepot.com",
                "lowes.com",
                "macys.com",
                "nordstrom.com",
                "kohls.com",
                "jcpenney.com",
                "sears.com",
                "oldnavy.com",
                "gap.com",
                "bananarepublic.com",
                "victoriassecret.com",
                "nytimes.com",
                "washingtonpost.com",
                "toast-restaurants.com",
                "uber.com",
                "mgm.uber.com",
                "lyft.com",
                "mail.instagram.com", // Instagram social platform
                "instagram.com",
                "facebook.com",
                "rejuvenation.com", // Rejuvenation retail
                "pbteen.com",       // Pottery Barn Teen
                "woot.com",         // Woot marketplace
            ];

            let is_legitimate_retail = legitimate_retail_domains
                .iter()
                .any(|domain| sender_domain.contains(domain));

            if !is_legitimate_retail {
                // High penalty since no Portuguese emails are expected
                score += 60;
                evidence.push(
                    "Portuguese language detected - unexpected in this environment".to_string(),
                );

                // Additional penalties for Portuguese scam patterns
                let scam_patterns = [
                    ("validação", "document validation scam"),
                    ("conferência", "conference/meeting scam"),
                    ("assinatura digital", "digital signature scam"),
                    ("notas pendentes", "pending notes scam"),
                    ("processo", "process completion scam"),
                ];

                for (pattern, description) in &scam_patterns {
                    if combined_text.to_lowercase().contains(pattern) {
                        score += 20;
                        evidence.push(format!("Portuguese scam pattern detected: {}", description));
                    }
                }
            }
        }

        FeatureScore {
            feature_name: self.name().to_string(),
            score,
            confidence: if score > 0 { 0.95 } else { 0.0 },
            evidence,
        }
    }

    fn name(&self) -> &str {
        "Portuguese Language"
    }
}
