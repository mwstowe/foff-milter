use super::DetectionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EcommerceScamsConfig {
    pub fake_products: FakeProducts,
    pub marketplace_fraud: MarketplaceFraud,
    pub pressure_tactics: PressureTactics,
    pub shopping_cart_abandonment: ShoppingCartAbandonment,
    pub counterfeit_indicators: CounterfeitIndicators,
    pub suspicious_pricing: SuspiciousPricing,
    pub legitimate_exclusions: LegitimateExclusions,
    pub confidence_scoring: ConfidenceScoring,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FakeProducts {
    pub electronics: Vec<String>,
    pub fashion: Vec<String>,
    pub health_supplements: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MarketplaceFraud {
    pub amazon_impersonation: Vec<String>,
    pub ebay_scams: Vec<String>,
    pub fake_reviews: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PressureTactics {
    pub flash_sales: Vec<String>,
    pub limited_time: Vec<String>,
    pub fake_discounts: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ShoppingCartAbandonment {
    pub recovery_scams: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CounterfeitIndicators {
    pub quality_claims: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SuspiciousPricing {
    pub too_good_to_be_true: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LegitimateExclusions {
    pub major_retailers: Vec<String>,
    pub brand_websites: Vec<String>,
    pub legitimate_marketplaces: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConfidenceScoring {
    pub fake_products: u32,
    pub marketplace_fraud: u32,
    pub pressure_tactics: u32,
    pub counterfeit_indicators: u32,
    pub suspicious_pricing: u32,
    pub shopping_cart_scams: u32,
}

pub struct EcommerceScamsDetector {
    config: EcommerceScamsConfig,
}

impl EcommerceScamsDetector {
    pub fn new(config: EcommerceScamsConfig) -> Self {
        Self { config }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: EcommerceScamsConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn check_ecommerce_scam(
        &self,
        subject: &str,
        body: &str,
        _sender: &str,
        sender_domain: &str,
    ) -> DetectionResult {
        // Check if sender is from legitimate retailer
        if self.is_legitimate_retailer(sender_domain) {
            return DetectionResult::no_match("EcommerceScams".to_string());
        }

        let mut confidence = 0;
        let mut reasons = Vec::new();
        let combined_text = format!("{} {}", subject, body).to_lowercase();

        // Check suspicious pricing (highest priority)
        if self.check_patterns(
            &combined_text,
            &self.config.suspicious_pricing.too_good_to_be_true,
        ) {
            confidence += self.config.confidence_scoring.suspicious_pricing;
            reasons.push("Suspicious pricing detected".to_string());
        }

        // Check marketplace fraud
        if self.check_patterns(
            &combined_text,
            &self.config.marketplace_fraud.amazon_impersonation,
        ) || self.check_patterns(&combined_text, &self.config.marketplace_fraud.ebay_scams)
            || self.check_patterns(&combined_text, &self.config.marketplace_fraud.fake_reviews)
        {
            confidence += self.config.confidence_scoring.marketplace_fraud;
            reasons.push("Marketplace fraud detected".to_string());
        }

        // Check fake products
        if self.check_patterns(&combined_text, &self.config.fake_products.electronics)
            || self.check_patterns(&combined_text, &self.config.fake_products.fashion)
            || self.check_patterns(
                &combined_text,
                &self.config.fake_products.health_supplements,
            )
        {
            confidence += self.config.confidence_scoring.fake_products;
            reasons.push("Fake product indicators detected".to_string());
        }

        // Check counterfeit indicators
        if self.check_patterns(
            &combined_text,
            &self.config.counterfeit_indicators.quality_claims,
        ) {
            confidence += self.config.confidence_scoring.counterfeit_indicators;
            reasons.push("Counterfeit product indicators detected".to_string());
        }

        // Check shopping cart abandonment scams
        if self.check_patterns(
            &combined_text,
            &self.config.shopping_cart_abandonment.recovery_scams,
        ) {
            confidence += self.config.confidence_scoring.shopping_cart_scams;
            reasons.push("Shopping cart abandonment scam detected".to_string());
        }

        // Check pressure tactics
        if self.check_patterns(&combined_text, &self.config.pressure_tactics.flash_sales)
            || self.check_patterns(&combined_text, &self.config.pressure_tactics.limited_time)
            || self.check_patterns(&combined_text, &self.config.pressure_tactics.fake_discounts)
        {
            confidence += self.config.confidence_scoring.pressure_tactics;
            reasons.push("Pressure tactics detected".to_string());
        }

        let matched = confidence > 0;
        let reason = if reasons.is_empty() {
            "No e-commerce scam indicators".to_string()
        } else {
            reasons.join(", ")
        };

        DetectionResult::new(matched, confidence, reason, "EcommerceScams".to_string())
    }

    fn check_patterns(&self, text: &str, patterns: &[String]) -> bool {
        patterns.iter().any(|pattern| {
            // Handle regex-like patterns for pricing
            if pattern.contains("\\$") {
                // Simple price pattern matching
                text.contains(&pattern.replace("\\$", "$").replace(".*", ""))
            } else {
                text.contains(pattern)
            }
        })
    }

    fn is_legitimate_retailer(&self, domain: &str) -> bool {
        let all_legitimate = [
            &self.config.legitimate_exclusions.major_retailers,
            &self.config.legitimate_exclusions.brand_websites,
            &self.config.legitimate_exclusions.legitimate_marketplaces,
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
        patterns.extend(self.config.fake_products.electronics.clone());
        patterns.extend(self.config.fake_products.fashion.clone());
        patterns.extend(self.config.fake_products.health_supplements.clone());
        patterns.extend(self.config.marketplace_fraud.amazon_impersonation.clone());
        patterns.extend(self.config.marketplace_fraud.ebay_scams.clone());
        patterns.extend(self.config.marketplace_fraud.fake_reviews.clone());
        patterns.extend(self.config.pressure_tactics.flash_sales.clone());
        patterns.extend(self.config.pressure_tactics.limited_time.clone());
        patterns.extend(self.config.pressure_tactics.fake_discounts.clone());
        patterns.extend(self.config.shopping_cart_abandonment.recovery_scams.clone());
        patterns.extend(self.config.counterfeit_indicators.quality_claims.clone());
        patterns.extend(self.config.suspicious_pricing.too_good_to_be_true.clone());
        patterns.sort();
        patterns.dedup();
        patterns
    }
}
