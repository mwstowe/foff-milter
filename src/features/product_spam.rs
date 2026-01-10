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

        // Heating/cooling product spam (use word boundaries to avoid false positives)
        let heating_products = [
            "heat up",
            "heating",
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

        // Check for heating product promotion (use word boundaries to avoid false positives)
        for product in &heating_products {
            // Use word boundaries for single words, exact match for phrases
            let matches = if product.contains(' ') {
                content.contains(product)
            } else {
                // Check for word boundaries to avoid substring matches
                content.split_whitespace().any(|word| word == *product)
                    || content
                        .split(&[' ', '.', ',', '!', '?', ';', ':', '\n', '\r'][..])
                        .any(|word| word == *product)
            };

            if matches {
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

        // Product rewards/offers pattern (exclude legitimate retailers)
        if (content.contains("reward") || content.contains("offer"))
            && (content.contains("take") || content.contains("get") || content.contains("claim"))
        {
            // Exclude legitimate retailers and ESP services
            let legitimate_retailers = [
                "1800flowers",
                "pulse.celebrations",
                "ftd",
                "teleflora",
                "proflowers",
                "shutterfly",
                "disney",
                "d23",
                "waltdisneypictures",
                "walgreens",
                "levis",
                "reolink",
                "nytimes",
                "usps",
                "docusign",
                "saily",
                "thinkvacuums",
                "sparkpost",    // ESP service
                "evergreentlc", // Tree care service
                "tmobile",
                "t-mobile",           // Telecom
                "capitaloneshopping", // Financial services
                // Entertainment industry
                "livenation",
                "ticketmaster",
                "stubhub",
                "eventbrite",
                // Publishing and media
                "gardensillustrated",
                "nytdirect", // Specific NY Times sender
                // Nurseries and gardening
                "swansonsnursery",
                // Fashion retail
                "musvc3",     // Mail.com ESP for fashion retailers
                "pierotucci", // Pierotucci leather goods
            ];
            let is_legitimate_retailer = legitimate_retailers
                .iter()
                .any(|retailer| sender_domain.contains(retailer));

            if !is_legitimate_retailer {
                score += 35;
                evidence.push("Product reward/offer promotion".to_string());
            }
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
