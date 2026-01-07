use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;

pub struct ProductSpamAnalyzer;

impl ProductSpamAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl FeatureExtractor for ProductSpamAnalyzer {
    fn name(&self) -> &str {
        "Product Spam"
    }

    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();

        let content = format!(
            "{} {} {}",
            context.subject.as_deref().unwrap_or(""),
            context.body.as_deref().unwrap_or(""),
            context.from_header.as_deref().unwrap_or("")
        )
        .to_lowercase();

        // Heating/cooling product spam
        let heating_products = [
            "heat up",
            "heating",
            "heater",
            "warm up",
            "cozy heat",
            "heat pro",
            "cooling",
            "air conditioner",
            "hvac",
            "thermostat",
        ];

        // Generic product promotion patterns
        let product_patterns = [
            "fastest way to",
            "best way to",
            "secret to",
            "solution for",
            "revolutionary",
            "breakthrough",
            "amazing",
            "incredible",
        ];

        // Suspicious promotional domains
        let promo_domains = [".click", ".shop", ".store", ".deals", ".offers"];

        let sender_domain = context
            .from_header
            .as_deref()
            .and_then(|from| from.split('@').nth(1))
            .unwrap_or("")
            .to_lowercase();

        // Check for heating product promotion
        for product in &heating_products {
            if content.contains(product) {
                score += 50;
                evidence.push(format!("Heating/cooling product promotion: '{}'", product));
                break;
            }
        }

        // Check for generic product promotion language
        for pattern in &product_patterns {
            if content.contains(pattern) {
                score += 30;
                evidence.push(format!("Generic product promotion pattern: '{}'", pattern));
                break;
            }
        }

        // Check for promotional domains
        for domain_suffix in &promo_domains {
            if sender_domain.contains(domain_suffix) {
                score += 25;
                evidence.push(format!("Promotional domain suffix: '{}'", domain_suffix));
                break;
            }
        }

        // Minimal content with only links (typical of product spam)
        let text_content = context.body.as_deref().unwrap_or("");
        let link_count = text_content.matches("http").count();
        let word_count = text_content.split_whitespace().count();

        if link_count > 0 && word_count < 20 {
            score += 40;
            evidence.push("Minimal content with promotional links".to_string());
        }

        // Product rewards/offers pattern
        if (content.contains("reward") || content.contains("offer"))
            && (content.contains("take") || content.contains("get") || content.contains("claim"))
        {
            score += 35;
            evidence.push("Product reward/offer promotion".to_string());
        }

        let confidence = if score > 0 { 0.85 } else { 0.1 };

        FeatureScore {
            feature_name: "Product Spam".to_string(),
            score,
            confidence,
            evidence,
        }
    }
}

impl Default for ProductSpamAnalyzer {
    fn default() -> Self {
        Self
    }
}
