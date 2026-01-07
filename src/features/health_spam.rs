use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;

pub struct HealthSpamAnalyzer;

impl HealthSpamAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl FeatureExtractor for HealthSpamAnalyzer {
    fn name(&self) -> &str {
        "Health Spam"
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

        // Health brand impersonation from non-health domains
        let health_brands = [
            "unitedhealthcare",
            "aetna",
            "cigna",
            "humana",
            "anthem",
            "bluecross",
            "kaiser",
            "medicaid",
            "medicare",
            "healthplan",
        ];

        let health_products = [
            "oral-b",
            "dental",
            "smile",
            "teeth",
            "toothbrush",
            "mouthwash",
            "vitamin",
            "supplement",
            "medicine",
            "prescription",
            "pharmacy",
            "health kit",
            "medical",
            "wellness",
            "fitness tracker",
        ];

        let sender_domain = context
            .from_header
            .as_deref()
            .and_then(|from| from.split('@').nth(1))
            .unwrap_or("")
            .to_lowercase();

        // Check for health brand impersonation
        for brand in &health_brands {
            if content.contains(brand) {
                let sender_domain_clean = sender_domain.replace(".", "").replace("-", "");
                let brand_clean = brand.replace(".", "").replace("-", "");

                // Only flag if domain doesn't contain the brand name at all
                if !sender_domain_clean.contains(&brand_clean) {
                    score += 80;
                    evidence.push(format!(
                        "Health brand '{}' impersonation from non-health domain",
                        brand
                    ));
                    break;
                }
            }
        }

        // Airline brand impersonation (specific patterns to avoid false positives)
        if content.contains("ana マイル") || content.contains("ana mile") || 
            (content.contains("ana") && (content.contains("航空") || content.contains("airline") || content.contains("マイル"))) {
            let sender_domain_clean = sender_domain.replace(".", "").replace("-", "");
            if !sender_domain_clean.contains("ana") {
                score += 90;
                evidence.push("ANA airline brand impersonation from non-airline domain".to_string());
            }
        }

        // Check for health product promotion from suspicious domains
        let suspicious_domains = ["cookfest", "fiveharvest", "foodie", "recipe", "kitchen"];
        let is_suspicious_domain = suspicious_domains.iter().any(|d| sender_domain.contains(d));

        if is_suspicious_domain {
            for product in &health_products {
                if content.contains(product) {
                    score += 60;
                    evidence.push(format!(
                        "Health product '{}' promotion from food/cooking domain",
                        product
                    ));
                    break;
                }
            }
        }

        // Health reward/gift scams
        if (content.contains("health") || content.contains("dental") || content.contains("medical"))
            && (content.contains("free") || content.contains("gift") || content.contains("reward"))
        {
            score += 40;
            evidence.push("Health-related free gift/reward offer".to_string());
        }

        let confidence = if score > 0 { 0.9 } else { 0.1 };

        FeatureScore {
            feature_name: "Health Spam".to_string(),
            score,
            confidence,
            evidence,
        }
    }
}

impl Default for HealthSpamAnalyzer {
    fn default() -> Self {
        Self
    }
}
