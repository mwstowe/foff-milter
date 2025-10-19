use super::DetectionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BrandImpersonationConfig {
    pub brands: BrandCategories,
    pub legitimate_domains: LegitimateDomainsConfig,
    pub confidence_scoring: ConfidenceScoring,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BrandCategories {
    pub airlines: BrandCategory,
    pub ecommerce: BrandCategory,
    pub telecom: BrandCategory,
    pub financial: BrandCategory,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BrandCategory {
    pub english: Option<Vec<String>>,
    pub japanese: Option<JapaneseBrands>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JapaneseBrands {
    pub decoded: Option<Vec<String>>,
    pub encoded: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LegitimateDomainsConfig {
    pub airlines: Option<Vec<String>>,
    pub ecommerce: Option<Vec<String>>,
    pub telecom: Option<Vec<String>>,
    pub financial: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConfidenceScoring {
    pub brand_match: u32,
    pub domain_mismatch: u32,
    pub suspicious_tld: u32,
    pub dkim_failure: u32,
    pub japanese_encoding: u32,
}

pub struct BrandImpersonationDetector {
    config: BrandImpersonationConfig,
}

impl BrandImpersonationDetector {
    pub fn new(config: BrandImpersonationConfig) -> Self {
        Self { config }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: BrandImpersonationConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn check_brand_impersonation(&self, from_header: &str, sender_domain: &str) -> DetectionResult {
        let mut confidence = 0;
        let mut reasons = Vec::new();
        let mut matched_brand = None;

        // Check all brand categories
        let categories = [
            ("airlines", &self.config.brands.airlines),
            ("ecommerce", &self.config.brands.ecommerce),
            ("telecom", &self.config.brands.telecom),
            ("financial", &self.config.brands.financial),
        ];

        for (category_name, category) in categories.iter() {
            if let Some(brand) = self.check_brand_in_category(from_header, category) {
                confidence += self.config.confidence_scoring.brand_match;
                reasons.push(format!("Brand match: {} in {}", brand, category_name));
                matched_brand = Some((category_name.to_string(), brand));
                break;
            }
        }

        // If brand matched, check if domain is legitimate
        if let Some((category, _brand)) = &matched_brand {
            if !self.is_legitimate_domain(sender_domain, category) {
                confidence += self.config.confidence_scoring.domain_mismatch;
                reasons.push(format!("Domain mismatch: {} not legitimate for {}", sender_domain, category));
            }
        }

        // Check for Japanese encoding
        if from_header.contains("=?utf-8?Q?") || from_header.contains("=E") {
            confidence += self.config.confidence_scoring.japanese_encoding;
            reasons.push("Japanese encoding detected".to_string());
        }

        let matched = confidence > 0;
        let reason = if reasons.is_empty() {
            "No brand impersonation indicators".to_string()
        } else {
            reasons.join(", ")
        };

        DetectionResult::new(matched, confidence, reason, "BrandImpersonation".to_string())
    }

    fn check_brand_in_category(&self, from_header: &str, category: &BrandCategory) -> Option<String> {
        let from_lower = from_header.to_lowercase();

        // Check English brands
        if let Some(english_brands) = &category.english {
            for brand in english_brands {
                if from_lower.contains(brand) {
                    return Some(brand.clone());
                }
            }
        }

        // Check Japanese brands (decoded)
        if let Some(japanese) = &category.japanese {
            if let Some(decoded_brands) = &japanese.decoded {
                for brand in decoded_brands {
                    if from_header.contains(brand) {
                        return Some(brand.clone());
                    }
                }
            }

            // Check Japanese brands (encoded)
            if let Some(encoded_brands) = &japanese.encoded {
                for brand in encoded_brands {
                    if from_header.contains(brand) {
                        return Some(brand.clone());
                    }
                }
            }
        }

        None
    }

    fn is_legitimate_domain(&self, domain: &str, category: &str) -> bool {
        let legitimate_domains = match category {
            "airlines" => &self.config.legitimate_domains.airlines,
            "ecommerce" => &self.config.legitimate_domains.ecommerce,
            "telecom" => &self.config.legitimate_domains.telecom,
            "financial" => &self.config.legitimate_domains.financial,
            _ => return false,
        };

        if let Some(domains) = legitimate_domains {
            for legitimate_domain in domains {
                if domain.ends_with(legitimate_domain) {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_all_brand_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();

        let categories = [
            &self.config.brands.airlines,
            &self.config.brands.ecommerce,
            &self.config.brands.telecom,
            &self.config.brands.financial,
        ];

        for category in categories.iter() {
            if let Some(english) = &category.english {
                patterns.extend(english.clone());
            }
            if let Some(japanese) = &category.japanese {
                if let Some(decoded) = &japanese.decoded {
                    patterns.extend(decoded.clone());
                }
                if let Some(encoded) = &japanese.encoded {
                    patterns.extend(encoded.clone());
                }
            }
        }

        patterns
    }
}
