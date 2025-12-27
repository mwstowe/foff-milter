use super::{FeatureExtractor, FeatureScore};
use crate::MailContext;

pub struct AdobeCampaignAnalyzer {
    legitimate_brands: Vec<String>,
}

impl Default for AdobeCampaignAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl AdobeCampaignAnalyzer {
    pub fn new() -> Self {
        Self {
            legitimate_brands: vec![
                "costco".to_string(),
                "walmart".to_string(),
                "target".to_string(),
                "bestbuy".to_string(),
                "homedepot".to_string(),
                "lowes".to_string(),
                "macys".to_string(),
                "nordstrom".to_string(),
                "kohls".to_string(),
                "jcpenney".to_string(),
                "sears".to_string(),
                "kmart".to_string(),
                "tjmaxx".to_string(),
                "marshalls".to_string(),
                "homegoods".to_string(),
                "bedbathandbeyond".to_string(),
                "williams-sonoma".to_string(),
                "potterybarn".to_string(),
                "westelm".to_string(),
                "crateandbarrel".to_string(),
                "cb2".to_string(),
                "anthropologie".to_string(),
                "urbanoutfitters".to_string(),
                "freepeople".to_string(),
                "bhldn".to_string(),
                "terrain".to_string(),
            ],
        }
    }

    fn is_adobe_campaign_domain(&self, domain: &str) -> bool {
        domain.contains(".cname.cjm.adobe.com")
            || domain.contains(".adobe.com")
            || domain.contains(".adobecampaign.com")
    }

    fn extract_brand_from_cname(&self, domain: &str) -> Option<String> {
        if let Some(cname_pos) = domain.find(".cname.cjm.adobe.com") {
            let brand_part = &domain[..cname_pos];
            // Extract the main brand from patterns like "digital.costco.com"
            if let Some(last_dot) = brand_part.rfind('.') {
                if let Some(second_last_dot) = brand_part[..last_dot].rfind('.') {
                    return Some(brand_part[second_last_dot + 1..last_dot].to_string());
                } else {
                    return Some(brand_part[..last_dot].to_string());
                }
            }
        }
        None
    }

    fn is_legitimate_brand(&self, brand: &str) -> bool {
        self.legitimate_brands
            .iter()
            .any(|b| b == &brand.to_lowercase())
    }
}

impl FeatureExtractor for AdobeCampaignAnalyzer {
    fn name(&self) -> &str {
        "Adobe Campaign Analysis"
    }

    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();
        let mut confidence = 0.0;

        // Check sender domain
        let sender_domain = context
            .from_header
            .as_deref()
            .and_then(|from| from.split('@').nth(1))
            .unwrap_or("");

        // Check envelope sender domain
        let envelope_sender_domain = context
            .sender
            .as_deref()
            .and_then(|sender| sender.split('@').nth(1))
            .unwrap_or("");

        // Check all relevant domains
        let domains_to_check = [sender_domain, envelope_sender_domain];

        for domain in &domains_to_check {
            if self.is_adobe_campaign_domain(domain) {
                evidence.push("Adobe Campaign infrastructure detected".to_string());

                // Extract brand from CNAME structure
                if let Some(brand) = self.extract_brand_from_cname(domain) {
                    if self.is_legitimate_brand(&brand) {
                        score -= 50; // Significant negative score for legitimate brands
                        evidence.push(format!("Legitimate brand using Adobe Campaign: {}", brand));
                        evidence.push(format!("Adobe Campaign CNAME structure: {}", domain));
                        confidence = 0.95;
                    } else {
                        // Unknown brand using Adobe Campaign - neutral but noted
                        evidence.push(format!("Unknown brand using Adobe Campaign: {}", brand));
                        evidence.push(format!("Adobe Campaign CNAME structure: {}", domain));
                        confidence = 0.7;
                    }
                } else {
                    // Direct Adobe Campaign domain
                    evidence.push(format!("Direct Adobe Campaign domain: {}", domain));
                    confidence = 0.8;
                }

                // Check for proper DKIM alignment with Adobe Campaign
                if let Some(auth_results) = context.headers.get("Authentication-Results") {
                    if let Some(extracted_brand) = &self.extract_brand_from_cname(domain) {
                        if auth_results.contains("dkim=pass")
                            && auth_results.contains(extracted_brand)
                        {
                            evidence.push("Adobe Campaign authentication validated".to_string());
                            score -= 10; // Additional bonus for proper auth
                        }
                    }
                }

                break; // Only process once
            }
        }

        FeatureScore {
            feature_name: "Adobe Campaign Analysis".to_string(),
            score,
            confidence,
            evidence,
        }
    }
}
