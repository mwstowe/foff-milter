use super::{FeatureExtractor, FeatureScore};
use crate::domain_utils::DomainUtils;
use crate::MailContext;
use regex::Regex;

pub struct InvoiceAnalyzer {
    scam_indicators: Vec<Regex>,
    legitimate_domains: Vec<String>,
}

impl Default for InvoiceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl InvoiceAnalyzer {
    pub fn new() -> Self {
        let scam_indicators = vec![
            Regex::new(r"(?i)(overdue|total amount|invoice number)").unwrap(),
            Regex::new(r"(?i)(within 24 hours|payment required|account suspended)").unwrap(),
            Regex::new(r"(?i)\b(click\s+here|verify\s+.*\s+account|update\s+.*\s+payment)\b")
                .unwrap(),
            // Generic fake invoice patterns
            Regex::new(r"(?i)(invoice\s+and\s+details\s+enclosed)").unwrap(),
            Regex::new(r"(?i)(thank\s+you\s+for\s+paying\s+for\s+order)").unwrap(),
            Regex::new(r"(?i)(thank\s+you\s+for\s+choosing\s+us.*invoice)").unwrap(),
        ];

        let legitimate_domains = vec![
            "iheart.com".to_string(),
            "wolfermans.com".to_string(),
            "harryandavid.com".to_string(),
            "adapthealth.com".to_string(),
            "sendgrid.net".to_string(),
            "mailchimp.com".to_string(),
            "constantcontact.com".to_string(),
            "dominos.com".to_string(),
            "e-offers.dominos.com".to_string(),
            "onestopplus.com".to_string(),
            "empower.com".to_string(),
            "walgreens.com".to_string(),
            "pulse.celebrations.com".to_string(), // 1-800-FLOWERS
            "aran.com".to_string(),
            "septicresponse.com".to_string(),
            "acemedseattle.com".to_string(),
            // Airlines and travel
            "airnz.co.nz".to_string(),
            "airfrance.com".to_string(),
            "lufthansa.com".to_string(),
            "delta.com".to_string(),
            "united.com".to_string(),
            "american.com".to_string(),
            "expedia.com".to_string(),
            "kayak.com".to_string(),
            // Telecom
            "tmobile.com".to_string(),
            "t-mobile.com".to_string(),
            // Financial services
            "capitaloneshopping.com".to_string(),
            // Health devices
            "withings.com".to_string(),
            "email.withings.com".to_string(),
        ];

        Self {
            scam_indicators,
            legitimate_domains,
        }
    }

    pub fn from_config(config: &crate::config_loader::InvoiceAnalysisConfig) -> Self {
        let scam_indicators: Vec<Regex> = config
            .scam_indicators
            .iter()
            .filter_map(|pattern| Regex::new(&format!("(?i){}", pattern)).ok())
            .collect();

        let legitimate_domains = vec![
            "iheart.com".to_string(),
            "wolfermans.com".to_string(),
            "harryandavid.com".to_string(),
            "adapthealth.com".to_string(),
            "sendgrid.net".to_string(),
            "mailchimp.com".to_string(),
            "constantcontact.com".to_string(),
            "dominos.com".to_string(),
            "e-offers.dominos.com".to_string(),
            "onestopplus.com".to_string(),
            "empower.com".to_string(),
            "walgreens.com".to_string(),
            "pulse.celebrations.com".to_string(), // 1-800-FLOWERS
            "aran.com".to_string(),
            "septicresponse.com".to_string(),
            "acemedseattle.com".to_string(),
            // Airlines and travel
            "airnz.co.nz".to_string(),
            "airfrance.com".to_string(),
            "lufthansa.com".to_string(),
            "delta.com".to_string(),
            "united.com".to_string(),
            "american.com".to_string(),
            "expedia.com".to_string(),
            "kayak.com".to_string(),
            // Telecom
            "tmobile.com".to_string(),
            "t-mobile.com".to_string(),
            // Financial services
            "capitaloneshopping.com".to_string(),
            // Health devices
            "withings.com".to_string(),
            "email.withings.com".to_string(),
        ];

        Self {
            scam_indicators,
            legitimate_domains,
        }
    }

    fn get_industry_multiplier(&self, sender: &str) -> f32 {
        let sender_lower = sender.to_lowercase();

        if sender_lower.contains("eflorist")
            || sender_lower.contains("floral")
            || sender_lower.contains("flower")
            || sender_lower.contains("ftd")
        {
            0.3 // 70% reduction for floral industry
        } else if sender_lower.contains("poshmark")
            || sender_lower.contains("ebay")
            || sender_lower.contains("etsy")
            || sender_lower.contains("mercari")
        {
            0.4 // 60% reduction for marketplace platforms
        } else if sender_lower.contains("medium")
            || sender_lower.contains("digest")
            || sender_lower.contains("newsletter")
            || sender_lower.contains("substack")
            || sender_lower.contains("nytimes")
        {
            0.2 // 80% reduction for newsletters
        } else if sender_lower.contains("travel")
            || sender_lower.contains("flight")
            || sender_lower.contains("airline")
            || sender_lower.contains("booking")
            || sender_lower.contains("expedia")
            || sender_lower.contains("kayak")
            || sender_lower.contains("airnz")
            || sender_lower.contains("airfrance")
            || sender_lower.contains("lufthansa")
            || sender_lower.contains("delta")
            || sender_lower.contains("united")
            || sender_lower.contains("american")
            || sender_lower.contains("ourvet")
            || sender_lower.contains("vetcove")
            || sender_lower.contains("mtasv")
            || sender_lower.contains("veterinary")
            || sender_lower.contains("pet")
        {
            0.1 // 90% reduction for travel industry and veterinary services
        } else {
            1.0 // No reduction for unknown senders
        }
    }
}

impl FeatureExtractor for InvoiceAnalyzer {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let body = context.body.as_deref().unwrap_or("");
        let subject = context
            .headers
            .get("Subject")
            .map(|s| s.as_str())
            .unwrap_or("");
        let full_text = format!("{} {}", subject, body);

        let mut score = 0;
        let mut evidence = Vec::new();

        // Check if sender is from legitimate domain using proper domain matching
        let sender = context.sender.as_deref().unwrap_or("");
        let from_header = context.from_header.as_deref().unwrap_or("");

        // Extract domains from sender and from_header
        let sender_domain = DomainUtils::extract_domain(sender).unwrap_or_default();
        let from_domain = if let Some(email_start) = from_header.find('<') {
            if let Some(email_end) = from_header.rfind('>') {
                if email_start + 1 < email_end {
                    let email = &from_header[email_start + 1..email_end];
                    DomainUtils::extract_domain(email).unwrap_or_default()
                } else {
                    DomainUtils::extract_domain(from_header).unwrap_or_default()
                }
            } else {
                DomainUtils::extract_domain(from_header).unwrap_or_default()
            }
        } else {
            DomainUtils::extract_domain(from_header).unwrap_or_default()
        };

        let is_legitimate =
            DomainUtils::matches_domain_list(&sender_domain, &self.legitimate_domains)
                || DomainUtils::matches_domain_list(&from_domain, &self.legitimate_domains);

        // Check for medical institutions
        let medical_institutions = [
            "labcorp.com",
            "quest.com",
            "mayo.org",
            "cleveland.org",
            "kaiser.org",
            "johnshopkins.org",
            "mountsinai.org",
            "cedars-sinai.org",
        ];
        let is_medical = medical_institutions.iter().any(|domain| {
            sender.to_lowercase().contains(domain) || from_header.to_lowercase().contains(domain)
        });

        // Treat medical institutions as legitimate
        let is_legitimate_or_medical = is_legitimate || is_medical;

        // Apply strong medical institution protection
        if is_medical {
            score = (score as f32 * 0.1) as i32; // 90% reduction for medical institutions
            evidence.push("Medical institution detected - score reduced".to_string());
        }

        // Check for invoice scam indicators with context awareness
        let click_here_regex = Regex::new(r"(?i)\bclick\s+here\b").unwrap();

        // Check for suspicious invoice patterns from non-business domains
        let has_generic_invoice_content = full_text
            .to_lowercase()
            .contains("invoice and details enclosed")
            || full_text
                .to_lowercase()
                .contains("thank you for paying for order")
            || (full_text
                .to_lowercase()
                .contains("thank you for choosing us")
                && full_text.to_lowercase().contains("invoice"));

        let is_suspicious_domain = sender_domain.ends_with(".hu")
            || sender_domain.contains("homerentals")
            || from_domain.ends_with(".hu")
            || from_domain.contains("homerentals");

        // Only flag generic/fake invoice patterns, not legitimate business invoices
        if has_generic_invoice_content && is_suspicious_domain && !is_legitimate_or_medical {
            score += 50;
            evidence.push(format!(
                "Generic fake invoice pattern from suspicious domain: {}",
                sender_domain
            ));
        }

        for pattern in &self.scam_indicators {
            if pattern.is_match(&full_text) {
                // Additional check for click here pattern to avoid URL false positives
                if pattern.as_str().contains("click\\s+here") {
                    // Simple check: ensure "click here" appears as standalone text
                    if !click_here_regex.is_match(&full_text) {
                        continue; // Skip this match
                    }
                    // Additional check: avoid matches in URLs by checking context
                    let lines: Vec<&str> = full_text.lines().collect();
                    let mut found_legitimate_click_here = false;
                    for line in lines {
                        if click_here_regex.is_match(line) && !line.contains("http") {
                            found_legitimate_click_here = true;
                            break;
                        }
                    }
                    if !found_legitimate_click_here {
                        continue; // Skip if only found in URLs
                    }
                }

                let base_score = if is_legitimate_or_medical { 0 } else { 30 }; // No score for legitimate senders
                let industry_multiplier = self.get_industry_multiplier(from_header);
                let adjusted_score = (base_score as f32 * industry_multiplier) as i32;

                score += adjusted_score;
                evidence.push(format!(
                    "Invoice scam pattern detected: {} (legitimate sender: {})",
                    pattern.as_str(),
                    is_legitimate_or_medical
                ));
            }
        }

        let confidence = if score > 0 { 0.9 } else { 0.0 };

        FeatureScore {
            feature_name: "Invoice Analysis".to_string(),
            score,
            confidence,
            evidence,
        }
    }

    fn name(&self) -> &str {
        "invoice_analyzer"
    }
}
