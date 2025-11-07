use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct InvoiceAnalyzer {
    // Compiled patterns for performance
    amount_patterns: Vec<Regex>,
    invoice_indicators: Vec<Regex>,
    urgency_patterns: Vec<Regex>,
    brand_impersonation: Vec<Regex>,
    suspicious_domains: Vec<Regex>,
}

#[derive(Debug, Clone)]
pub struct InvoiceAnalysis {
    pub is_fake_invoice: bool,
    pub confidence_score: f32,
    pub detected_patterns: Vec<String>,
    pub risk_factors: Vec<String>,
}

impl InvoiceAnalyzer {
    pub fn new() -> Self {
        Self {
            amount_patterns: vec![
                Regex::new(r"(?i)\$\d{2,4}\.\d{2}").unwrap(),
                Regex::new(r"(?i)(total|amount|charge|bill|due).*\$\d+").unwrap(),
                Regex::new(r"(?i)\$\d+.*\d+.*hours").unwrap(),
            ],
            invoice_indicators: vec![
                Regex::new(r"(?i)(invoice|bill|receipt|charge|payment|overdue)").unwrap(),
                Regex::new(r"(?i)(nota fiscal|documento|nfse|eletronica|disponivel)").unwrap(),
                Regex::new(r"(?i)invoice\s*#?\s*\d+").unwrap(),
                Regex::new(r"(?i)(inspecoes|tecnicas|solides|ponto)").unwrap(),
            ],
            urgency_patterns: vec![
                Regex::new(r"(?i)(24 hours|expires|urgent|immediate|suspend|cancel)").unwrap(),
                Regex::new(r"(?i)(will be.*charged|auto.*renew|debited)").unwrap(),
            ],
            brand_impersonation: vec![
                Regex::new(r"(?i)(norton|mcafee|microsoft|apple)").unwrap(),
                Regex::new(r"(?i)(antivirus|security|protection).*alert").unwrap(),
            ],
            suspicious_domains: vec![
                Regex::new(r"@[^@]*\.(tk|ml|ga|cf|gq|top|click|delivery|shop)$").unwrap(),
                Regex::new(r"documento\d+@").unwrap(),
                Regex::new(r"@[a-z0-9]{8,15}\.[a-z]{2,4}$").unwrap(),
                Regex::new(r"@.*\.zemark\.delivery$").unwrap(),
            ],
        }
    }

    pub fn analyze(&self, subject: &str, body: &str, sender: &str, from_header: &str) -> InvoiceAnalysis {
        let mut score = 0.0;
        let mut patterns = Vec::new();
        let mut risks = Vec::new();

        let combined_text = format!("{} {} {}", subject, body, from_header);

        // Skip analysis for legitimate business domains
        if self.is_legitimate_business(sender, from_header) {
            return InvoiceAnalysis {
                is_fake_invoice: false,
                confidence_score: 0.0,
                detected_patterns: vec!["Legitimate business domain".to_string()],
                risk_factors: vec![],
            };
        }

        // Skip analysis for subscription services
        if self.is_subscription_service(&combined_text, sender) {
            return InvoiceAnalysis {
                is_fake_invoice: false,
                confidence_score: 0.0,
                detected_patterns: vec!["Subscription service".to_string()],
                risk_factors: vec![],
            };
        }

        // Check for monetary amounts (high weight)
        if self.has_suspicious_amounts(&combined_text) {
            score += 30.0;
            patterns.push("Suspicious monetary amounts".to_string());
        }

        // Check invoice indicators
        let invoice_matches = self.count_pattern_matches(&self.invoice_indicators, &combined_text);
        if invoice_matches > 0 {
            score += invoice_matches as f32 * 15.0;
            patterns.push(format!("Invoice indicators ({})", invoice_matches));
        }

        // Check urgency patterns (only if invoice indicators are present)
        let urgency_matches = self.count_pattern_matches(&self.urgency_patterns, &combined_text);
        if urgency_matches > 0 && invoice_matches > 0 {
            score += urgency_matches as f32 * 20.0;
            patterns.push(format!("Urgency + invoice patterns ({})", urgency_matches));
        }

        // Check brand impersonation
        if self.has_brand_impersonation(&combined_text, sender) {
            score += 35.0;
            patterns.push("Brand impersonation detected".to_string());
            risks.push("Impersonating trusted brand".to_string());
        }

        // Check suspicious sender domains
        if self.has_suspicious_domain(sender) || self.has_suspicious_domain(from_header) {
            score += 25.0;
            patterns.push("Suspicious sender domain".to_string());
            risks.push("Untrusted domain".to_string());
        }

        // Check sender/brand mismatch
        if self.has_sender_brand_mismatch(&combined_text, sender) {
            score += 40.0;
            patterns.push("Sender/brand mismatch".to_string());
            risks.push("Domain doesn't match claimed brand".to_string());
        }

        // Normalize score to 0-100
        let confidence = (score / 100.0).min(1.0);
        
        InvoiceAnalysis {
            is_fake_invoice: confidence > 0.4, // Balanced threshold
            confidence_score: confidence,
            detected_patterns: patterns,
            risk_factors: risks,
        }
    }

    fn has_suspicious_amounts(&self, text: &str) -> bool {
        // Look for specific amount patterns that are common in scams
        let suspicious_amounts = [
            r"\$295\.70", r"\$299\.99", r"\$399\.99", r"\$49\.99",
            r"\$\d{2,3}\.\d{2}.*24.*hours",
        ];
        
        for pattern_str in &suspicious_amounts {
            if let Ok(pattern) = Regex::new(&format!("(?i){}", pattern_str)) {
                if pattern.is_match(text) {
                    return true;
                }
            }
        }
        false
    }

    fn count_pattern_matches(&self, patterns: &[Regex], text: &str) -> usize {
        patterns.iter().map(|p| if p.is_match(text) { 1 } else { 0 }).sum()
    }

    fn has_brand_impersonation(&self, text: &str, sender: &str) -> bool {
        // Only check for major tech/security brands that are commonly impersonated in invoice scams
        let high_risk_brands = ["norton", "mcafee", "microsoft", "apple"];
        
        for brand in &high_risk_brands {
            let brand_pattern = Regex::new(&format!("(?i){}", brand)).unwrap();
            if brand_pattern.is_match(text) {
                // Exclude HTML namespace references and technical content (be specific)
                let html_exclusions = [
                    "schemas-microsoft-com", "x-apple-data-detectors", "xmlns:",
                    "microsoft-com:office", "microsoft-com:vml", "appleLinks",
                    "Apple-Mail-Boundary",
                ];
                
                let mut is_html_reference = false;
                for exclusion in &html_exclusions {
                    if text.contains(exclusion) {
                        is_html_reference = true;
                        break;
                    }
                }
                
                // Additional check: if it contains HTML but also has scam indicators, don't exclude
                if is_html_reference {
                    let scam_indicators = ["overdue", "total amount", "invoice number", "24 hours"];
                    let has_scam_language = scam_indicators.iter().any(|&indicator| 
                        text.to_lowercase().contains(indicator)
                    );
                    if has_scam_language {
                        is_html_reference = false; // Don't exclude if it has scam language
                    }
                }
                
                if is_html_reference {
                    continue;
                }
                
                let domain_pattern = Regex::new(&format!("(?i)@.*{}.*\\.", brand)).unwrap();
                if !domain_pattern.is_match(sender) {
                    return true;
                }
            }
        }
        false
    }

    fn has_suspicious_domain(&self, email: &str) -> bool {
        self.suspicious_domains.iter().any(|p| p.is_match(email))
    }

    fn has_sender_brand_mismatch(&self, text: &str, sender: &str) -> bool {
        // Only check for brands commonly used in invoice scams
        let invoice_scam_brands = ["norton", "mcafee", "microsoft", "apple"];
        
        for brand in &invoice_scam_brands {
            let brand_pattern = Regex::new(&format!("(?i){}", brand)).unwrap();
            if brand_pattern.is_match(text) {
                // Exclude HTML namespace references and technical content (be specific)
                let html_exclusions = [
                    "schemas-microsoft-com", "x-apple-data-detectors", "xmlns:",
                    "microsoft-com:office", "microsoft-com:vml", "appleLinks",
                    "Apple-Mail-Boundary",
                ];
                
                let mut is_html_reference = false;
                for exclusion in &html_exclusions {
                    if text.contains(exclusion) {
                        is_html_reference = true;
                        break;
                    }
                }
                
                // Additional check: if it contains HTML but also has scam indicators, don't exclude
                if is_html_reference {
                    let scam_indicators = ["overdue", "total amount", "invoice number", "24 hours"];
                    let has_scam_language = scam_indicators.iter().any(|&indicator| 
                        text.to_lowercase().contains(indicator)
                    );
                    if has_scam_language {
                        is_html_reference = false; // Don't exclude if it has scam language
                    }
                }
                
                if is_html_reference {
                    continue;
                }
                
                let domain_pattern = Regex::new(&format!("(?i)@.*{}.*\\.", brand)).unwrap();
                if !domain_pattern.is_match(sender) {
                    return true;
                }
            }
        }
        false
    }

    fn is_legitimate_business(&self, sender: &str, from_header: &str) -> bool {
        let legitimate_domains = [
            "amazon.com", "paypal.com", "microsoft.com", "apple.com", "google.com",
            "fidelity.com", "adapthealth.com", "bcdtravel.com", "backstage.com",
            "arrived.com", "seattle.gov", "netsuite.com", "salesforce.com",
            "quickbooks.com", "stripe.com", "square.com", "shopify.com",
            "mailchimp.com", "constantcontact.com", "sendgrid.net",
            "adapthealthmarketplace.com"
        ];

        for domain in &legitimate_domains {
            if sender.contains(domain) || from_header.contains(domain) {
                return true;
            }
        }

        // Check for legitimate business patterns
        let business_patterns = [
            r"@.*\.(gov|edu|mil)$",
            r"@.*\.(bank|credit|financial)\.com$",
            r"@.*receipt.*\.com$",
            r"@.*invoice.*\.com$",
        ];

        for pattern_str in &business_patterns {
            if let Ok(pattern) = Regex::new(pattern_str) {
                if pattern.is_match(sender) || pattern.is_match(from_header) {
                    return true;
                }
            }
        }

        false
    }

    fn is_subscription_service(&self, text: &str, sender: &str) -> bool {
        // Check for subscription service patterns
        let subscription_patterns = [
            "trial", "membership", "streaming", "monthly", 
            "annual", "cancel anytime", "free trial", "premium"
        ];
        
        let subscription_domains = [
            "disneyplus", "netflix", "spotify", "hulu", "amazon", "apple",
            "microsoft", "adobe", "zoom", "dropbox", "slack"
        ];
        
        // If it's from a known subscription service
        for domain in &subscription_domains {
            if sender.contains(domain) {
                return true;
            }
        }
        
        // If it contains subscription language but also scam indicators, don't exclude
        let scam_indicators = ["overdue", "total amount", "invoice number", "24 hours", "will be charged"];
        let has_scam_language = scam_indicators.iter().any(|&indicator| 
            text.to_lowercase().contains(indicator)
        );
        
        if has_scam_language {
            return false; // Don't exclude scams even if they mention subscriptions
        }
        
        // If it contains subscription language
        let mut subscription_indicators = 0;
        for pattern in &subscription_patterns {
            if text.to_lowercase().contains(pattern) {
                subscription_indicators += 1;
            }
        }
        
        subscription_indicators >= 2
    }
}
