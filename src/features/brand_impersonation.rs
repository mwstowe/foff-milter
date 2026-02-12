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

        brand_patterns.insert("coinbase".to_string(), vec![r"(?i)\bcoinbase\b".to_string()]);
        legitimate_domains.insert("coinbase".to_string(), vec!["coinbase.com".to_string()]);

        brand_patterns.insert(
            "mcdonalds".to_string(),
            vec![r"(?i)\bmcdonalds?\b".to_string(), r"(?i)\bmcd\b".to_string()],
        );
        legitimate_domains.insert(
            "mcdonalds".to_string(),
            vec!["mcdonalds.com".to_string(), "sparkpostmail.com".to_string()],
        );

        brand_patterns.insert("butcherbox".to_string(), vec![r"(?i)\bbutcher\s*box\b".to_string()]);
        legitimate_domains.insert("butcherbox".to_string(), vec!["butcherbox.com".to_string()]);

        brand_patterns.insert("aldi".to_string(), vec![r"(?i)\baldi\b".to_string()]);
        legitimate_domains.insert("aldi".to_string(), vec!["aldi.com".to_string(), "aldi.us".to_string()]);

        brand_patterns.insert("publix".to_string(), vec![r"(?i)\bpublix\b".to_string()]);
        legitimate_domains.insert("publix".to_string(), vec!["publix.com".to_string()]);

        brand_patterns.insert(
            "ace_hardware".to_string(),
            vec![
                r"(?i)\bace\s*hardware\b".to_string(),
                r"(?i)\bace\s*stores?\b".to_string(),
            ],
        );
        legitimate_domains.insert(
            "ace_hardware".to_string(),
            vec!["acehardware.com".to_string(), "acehdwr.com".to_string()],
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

        brand_patterns.insert(
            "lowes".to_string(),
            vec![r"(?i)\blowe'?s\b".to_string()], // Match "lowes" or "lowe's" with word boundary
        );
        legitimate_domains.insert(
            "lowes".to_string(),
            vec![
                "lowes.com".to_string(),
                "mail.capitaloneshopping.com".to_string(), // Capital One Shopping affiliate
            ],
        );

        brand_patterns.insert(
            "tinnitus".to_string(),
            vec![
                r"(?i)\btinnitus\s*\d+\b".to_string(),
                r"(?i)\bhearing\s*(aid|device)\b".to_string(),
            ],
        );
        legitimate_domains.insert("tinnitus".to_string(), vec!["hearingaid.com".to_string()]);

        brand_patterns.insert(
            "aaa".to_string(),
            vec![
                r"(?i)\baaa\b".to_string(),
                r"(?i)\btriple\s*a\b".to_string(),
                r"(?i)\bamerican\s*automobile\s*association\b".to_string(),
            ],
        );
        legitimate_domains.insert(
            "aaa".to_string(),
            vec!["aaa.com".to_string(), "aaa.org".to_string()],
        );

        brand_patterns.insert(
            "tractor_supply".to_string(),
            vec![
                r"(?i)\btractor\s*supply\b".to_string(),
                r"(?i)\btractor-supply\b".to_string(),
                r"(?i)\bts\s*co\b".to_string(),
            ],
        );
        legitimate_domains.insert(
            "tractor_supply".to_string(),
            vec!["tractorsupply.com".to_string()],
        );

        brand_patterns.insert(
            "tmobile".to_string(),
            vec![
                r"(?i)\bt-?mobile\b".to_string(),
                r"(?i)\btmobile\b".to_string(),
            ],
        );
        legitimate_domains.insert(
            "tmobile".to_string(),
            vec!["t-mobile.com".to_string(), "tmobile.com".to_string()],
        );

        brand_patterns.insert(
            "att".to_string(),
            vec![r"(?i)\bat&t\b".to_string()], // Only match "at&t", not bare "att"
        );
        legitimate_domains.insert("att".to_string(), vec!["att.com".to_string()]);

        brand_patterns.insert("verizon".to_string(), vec![r"(?i)\bverizon\b".to_string()]);
        legitimate_domains.insert(
            "verizon".to_string(),
            vec!["verizon.com".to_string(), "verizon.net".to_string()],
        );

        brand_patterns.insert(
            "costco".to_string(),
            vec![
                r"(?i)\bcostco\b".to_string(),
                r"(?i)\bc0stc0\b".to_string(), // Character substitution (0 for O)
            ],
        );
        legitimate_domains.insert(
            "costco".to_string(),
            vec!["costco.com".to_string(), "costco.ca".to_string()],
        );

        brand_patterns.insert("keurig".to_string(), vec![r"(?i)\bkeurig\b".to_string()]);
        legitimate_domains.insert(
            "keurig".to_string(),
            vec!["keurig.com".to_string(), "keurig.ca".to_string()],
        );

        // Financial services brands
        brand_patterns.insert(
            "fidelity".to_string(),
            vec![
                r"(?i)\bfidelity\s*investments?\b".to_string(),
                r"(?i)\bfidelity\s*brokerage\b".to_string(),
            ],
        );
        legitimate_domains.insert(
            "fidelity".to_string(),
            vec![
                "fidelity.com".to_string(),
                "fidelityinvestments.com".to_string(),
            ],
        );

        brand_patterns.insert(
            "schwab".to_string(),
            vec![
                r"(?i)\bschwab\b".to_string(),
                r"(?i)\bcharles\s*schwab\b".to_string(),
            ],
        );
        legitimate_domains.insert(
            "schwab".to_string(),
            vec!["schwab.com".to_string(), "aboutschwab.com".to_string()],
        );

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
        let regex_lowes = Regex::new(r"(?i)\blowe'?s\s").unwrap();

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
        if regex_lowes.is_match(&text_lower) {
            detected_brands.push("lowes".to_string());
        }
        if text_lower.contains("tinnitus") {
            detected_brands.push("tinnitus".to_string());
        }

        detected_brands
    }

    fn is_legitimate_domain_for_brand(&self, brand: &str, domain: &str) -> bool {
        // Check if this is a legitimate multi-brand company (cashback, deals, affiliates)
        if self.is_legitimate_multi_brand_company(domain) {
            return true;
        }

        if let Some(legitimate) = self.legitimate_domains.get(brand) {
            if legitimate
                .iter()
                .any(|d| domain == d || domain.ends_with(&format!(".{}", d)))
            {
                return true;
            }
        }

        // Handle legitimate business partnerships
        match brand {
            "amazon" => {
                // Amazon partnerships with financial institutions and logistics
                domain.contains("fidelity")
                    || domain.contains("chase")
                    || domain.contains("wellsfargo")
                    || domain.contains("onestopplus")
                    || domain.contains("empower")
                    // Legitimate retailers that sell on Amazon
                    || domain.contains("asus.com")
                    // Shipping/logistics partners that deliver Amazon packages
                    || domain.contains("ups.com")
                    || domain.contains("fedex.com")
                    || domain.contains("usps.com")
            }
            _ => false,
        }
    }

    /// Check if domain belongs to legitimate multi-brand companies
    fn is_legitimate_multi_brand_company(&self, domain: &str) -> bool {
        let multi_brand_companies = [
            // Cashback and rewards services
            "capitaloneshopping.com",
            "accounts.capitaloneshopping.com",
            "rakuten.com",
            "ebates.com",
            "honey.com",
            "ibotta.com",
            "dosh.com",
            // Deal aggregators and comparison sites
            "slickdeals.net",
            "dealnews.com",
            "retailmenot.com",
            "groupon.com",
            "woot.com",
            "fatwallet.com",
            // Affiliate marketing platforms
            "commission-junction.com",
            "cj.com",
            "shareasale.com",
            "linkshare.com",
            "impact.com",
            // Price comparison and shopping engines
            "shopping.google.com",
            "nextag.com",
            "shopzilla.com",
            "pricegrabber.com",
            "shopping.yahoo.com",
            // Coupon and deal sites
            "coupons.com",
            "coupon.com",
            "valpak.com",
            "redplum.com",
        ];

        multi_brand_companies
            .iter()
            .any(|company| domain == *company || domain.ends_with(&format!(".{}", company)))
    }
}

impl FeatureExtractor for BrandImpersonationFeature {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();
        let mut confidence: f32 = 0.0;

        // Skip brand impersonation detection for legitimate newsletters and ESPs
        // Check from_header first as it's more reliable for ESP detection
        let sender_domain = context
            .from_header
            .as_ref()
            .or(context.sender.as_ref())
            .and_then(|s| self.extract_domain(s))
            .unwrap_or_default()
            .to_lowercase();

        let legitimate_newsletter_esps = ["sendgrid", "medium", "substack", "mailchimp"];
        if legitimate_newsletter_esps
            .iter()
            .any(|esp| sender_domain.contains(esp))
        {
            return FeatureScore {
                feature_name: "Brand Impersonation".to_string(),
                score: 0,
                confidence: 0.0,
                evidence: vec![],
            };
        }

        // Check for recipient domain impersonation in display name
        if let Some(to_header) = context.headers.get("to") {
            if let Some(recipient_domain) = self.extract_domain(to_header) {
                let display_name = context
                    .headers
                    .get("from")
                    .and_then(|from| {
                        // Extract display name from "Display Name <email@domain.com>"
                        from.find('<')
                            .map(|start| from[..start].trim().to_lowercase())
                    })
                    .unwrap_or_default();

                // Extract sender domain from sender or from_header
                let sender_domain = context
                    .sender
                    .as_ref()
                    .or(context.from_header.as_ref())
                    .and_then(|s| self.extract_domain(s))
                    .unwrap_or_default()
                    .to_lowercase();

                // Check if display name contains recipient domain (without dots) but sender is from different domain
                let recipient_domain_nodots = recipient_domain.replace('.', "");
                let recipient_domain_parts: Vec<&str> = recipient_domain.split('.').collect();

                // Check if display name contains the main domain part (before TLD)
                let main_domain_part = recipient_domain_parts.first().unwrap_or(&"");
                let contains_domain = display_name.contains(&recipient_domain_nodots)
                    || display_name.contains(&recipient_domain.replace('.', "_"))
                    || display_name.contains(&recipient_domain.replace('.', "-"))
                    || (!main_domain_part.is_empty() && display_name.contains(main_domain_part));

                if !display_name.is_empty() && contains_domain && sender_domain != recipient_domain
                {
                    score += 150;
                    confidence = 95.0;
                    evidence.push(format!(
                        "CRITICAL: Display name '{}' impersonates recipient domain '{}' but sender is from '{}'",
                        display_name, recipient_domain, sender_domain
                    ));
                }
            }
        }

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
