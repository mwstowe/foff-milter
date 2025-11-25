use crate::config_loader::ConfigLoader;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct InvoiceAnalyzer {
    // Compiled patterns for performance
    invoice_indicators: Vec<Regex>,
    urgency_patterns: Vec<Regex>,
    suspicious_domains: Vec<Regex>,
    legitimate_domains: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InvoiceAnalysis {
    pub is_fake_invoice: bool,
    pub confidence_score: f32,
    pub detected_patterns: Vec<String>,
    pub risk_factors: Vec<String>,
}

impl InvoiceAnalyzer {
    pub fn with_features_dir(features_dir: &str) -> Self {
        let legitimate_domains = ConfigLoader::get_all_legitimate_domains(features_dir)
            .unwrap_or_else(|e| {
                eprintln!("Warning: Failed to load legitimate domains config: {}", e);
                vec![
                    // Fallback hardcoded domains if config fails to load
                    "chase.com".to_string(),
                    "wellsfargo.com".to_string(),
                    "bankofamerica.com".to_string(),
                    "citi.com".to_string(),
                    "info6.citi.com".to_string(),
                    "paypal.com".to_string(),
                ]
            });

        eprintln!(
            "Invoice analyzer loaded {} legitimate domains",
            legitimate_domains.len()
        );

        Self {
            legitimate_domains,
            invoice_indicators: vec![
                Regex::new(r"(?i)invoice").unwrap(),
                Regex::new(r"(?i)bill").unwrap(),
                Regex::new(r"(?i)payment").unwrap(),
                Regex::new(r"(?i)due").unwrap(),
                Regex::new(r"(?i)overdue").unwrap(),
                Regex::new(r"(?i)receipt").unwrap(),
                Regex::new(r"(?i)statement").unwrap(),
                Regex::new(r"(?i)faturamento").unwrap(),
                Regex::new(r"(?i)cobrança").unwrap(),
                Regex::new(r"(?i)documento fiscal").unwrap(),
                Regex::new(r"(?i)nota fiscal").unwrap(),
                Regex::new(r"(?i)facturación").unwrap(),
            ],
            suspicious_domains: vec![
                Regex::new(r"(?i)bit\.ly").unwrap(),
                Regex::new(r"(?i)tinyurl\.com").unwrap(),
                Regex::new(r"(?i)t\.co").unwrap(),
                Regex::new(r"(?i)goo\.gl").unwrap(),
            ],
            urgency_patterns: vec![
                Regex::new(r"(?i)urgent").unwrap(),
                Regex::new(r"(?i)immediate").unwrap(),
                Regex::new(r"(?i)expires today").unwrap(),
                Regex::new(r"(?i)act now").unwrap(),
                Regex::new(r"(?i)limited time").unwrap(),
            ],
        }
    }
}

impl Default for InvoiceAnalyzer {
    fn default() -> Self {
        // Try common paths for features directory
        let features_paths = [
            "features",
            "/etc/foff-milter/features",
            "/usr/local/etc/foff-milter/features",
        ];

        for path in &features_paths {
            if std::path::Path::new(&format!("{}/legitimate_domains.toml", path)).exists() {
                // Silent loading for default - will be replaced by with_features_dir() later
                let legitimate_domains =
                    ConfigLoader::get_all_legitimate_domains(path).unwrap_or_else(|_| vec![]);
                return Self::new_with_domains(legitimate_domains);
            }
        }

        // Fallback to hardcoded if no config found
        let legitimate_domains = ConfigLoader::get_all_legitimate_domains("features")
            .unwrap_or_else(|_| {
                vec![
                    // Fallback hardcoded domains if config fails to load
                    "chase.com".to_string(),
                    "wellsfargo.com".to_string(),
                    "bankofamerica.com".to_string(),
                    "citi.com".to_string(),
                    "info6.citi.com".to_string(),
                    "paypal.com".to_string(),
                ]
            });

        Self::new_with_domains(legitimate_domains)
    }
}

impl InvoiceAnalyzer {
    pub fn new_with_domains(legitimate_domains: Vec<String>) -> Self {
        Self {
            invoice_indicators: vec![
                Regex::new(r"(?i)\binvoice\b").unwrap(),
                Regex::new(r"(?i)\bbill\b").unwrap(),
                Regex::new(r"(?i)\bstatement\b").unwrap(),
                Regex::new(r"(?i)\breceipt\b").unwrap(),
                Regex::new(r"(?i)\bpayment\b").unwrap(),
                Regex::new(r"(?i)\bdue\b").unwrap(),
                Regex::new(r"(?i)\bamount\b").unwrap(),
                Regex::new(r"(?i)\btotal\b").unwrap(),
            ],
            urgency_patterns: vec![
                Regex::new(r"(?i)\burgent\b").unwrap(),
                Regex::new(r"(?i)\bimmediate\b").unwrap(),
                Regex::new(r"(?i)\boverdue\b").unwrap(),
                Regex::new(r"(?i)\bexpir(e|ing|ed)\b").unwrap(),
                Regex::new(r"(?i)\bsuspend(ed)?\b").unwrap(),
                Regex::new(r"(?i)\bcancel(led)?\b").unwrap(),
                Regex::new(r"(?i)\b(24|48)\s*hours?\b").unwrap(),
                Regex::new(r"(?i)\bact\s+now\b").unwrap(),
            ],
            suspicious_domains: vec![
                Regex::new(r"(?i)\.tk$").unwrap(),
                Regex::new(r"(?i)\.ml$").unwrap(),
                Regex::new(r"(?i)\.ga$").unwrap(),
                Regex::new(r"(?i)\.cf$").unwrap(),
                Regex::new(r"(?i)\.gq$").unwrap(),
                Regex::new(r"(?i)\.ru$").unwrap(),
                Regex::new(r"(?i)\.cn$").unwrap(),
            ],
            legitimate_domains,
        }
    }

    pub fn new() -> Self {
        Self::new_with_domains(vec![])
    }

    pub fn analyze(
        &self,
        subject: &str,
        body: &str,
        sender: &str,
        from_header: &str,
        extracted_media_text: &str,
    ) -> InvoiceAnalysis {
        let mut score = 0.0;
        let mut patterns = Vec::new();
        let mut risk_factors = Vec::new();

        let text = format!("{} {} {}", subject, body, extracted_media_text);

        // Check for invoice indicators
        let mut invoice_indicators = 0;
        for pattern in &self.invoice_indicators {
            if pattern.is_match(&text) {
                invoice_indicators += 1;
            }
        }

        if invoice_indicators > 0 {
            patterns.push(format!("Invoice indicators ({})", invoice_indicators));
            score += invoice_indicators as f32 * 10.0;
        }

        // Check for urgency patterns
        let mut urgency_count = 0;
        for pattern in &self.urgency_patterns {
            if pattern.is_match(&text) {
                urgency_count += 1;
            }
        }

        if urgency_count > 0 {
            patterns.push(format!("Urgency patterns ({})", urgency_count));
            score += urgency_count as f32 * 15.0;
        }

        // Check for brand + delivery context combinations (phishing specific)
        let delivery_phishing_patterns = vec![
            Regex::new(r"(?i)delivery.*information.*paypal").unwrap(),
            Regex::new(r"(?i)paypal.*delivery.*information").unwrap(),
            Regex::new(r"(?i)shipping.*notification.*(paypal|amazon|ebay)").unwrap(),
            Regex::new(r"(?i)(paypal|amazon|ebay).*shipping.*notification").unwrap(),
        ];

        let has_delivery_context =
            text.to_lowercase().contains("delivery") || text.to_lowercase().contains("shipping");
        let has_financial_brand = text.to_lowercase().contains("paypal")
            || text.to_lowercase().contains("amazon")
            || text.to_lowercase().contains("ebay");

        // Only flag if delivery + brand from non-legitimate domain
        if has_delivery_context
            && has_financial_brand
            && !self.is_legitimate_business(sender, from_header)
        {
            for pattern in &delivery_phishing_patterns {
                if pattern.is_match(&text) {
                    patterns.push("Delivery phishing detected".to_string());
                    score += 60.0;
                    risk_factors.push(
                        "Financial brand in delivery context from suspicious domain".to_string(),
                    );
                    break;
                }
            }
        }

        // Check for suspicious domains
        for pattern in &self.suspicious_domains {
            if pattern.is_match(sender) || pattern.is_match(from_header) {
                patterns.push("Suspicious domain".to_string());
                score += 25.0;
                break;
            }
        }

        // Check for academic domain abuse
        let academic_patterns = vec![
            Regex::new(r"(?i)\.ac\.[a-z]{2}$").unwrap(),
            Regex::new(r"(?i)\.edu$").unwrap(),
            Regex::new(r"(?i)\.edu\.[a-z]{2}$").unwrap(),
        ];

        for pattern in &academic_patterns {
            if (pattern.is_match(sender) || pattern.is_match(from_header))
                && (text.to_lowercase().contains("paypal")
                    || text.to_lowercase().contains("invoice")
                    || text.to_lowercase().contains("delivery")
                    || text.to_lowercase().contains("payment"))
            {
                patterns.push("Academic domain abuse".to_string());
                score += 75.0;
                risk_factors
                    .push("Academic domain used for commercial/financial content".to_string());
                break;
            }
        }

        // Check for transport/logistics scam patterns
        let transport_scam_patterns = vec![
            Regex::new(r"(?i)(conhecimento.*transporte|CT-e|DACTE)").unwrap(),
            Regex::new(r"(?i)(transporte.*eletr[ôo]nico)").unwrap(),
            Regex::new(r"(?i)(arquivo.*XML.*transporte)").unwrap(),
            Regex::new(r"(?i)(documento.*autorizado.*SINIEF)").unwrap(),
        ];

        for pattern in &transport_scam_patterns {
            if pattern.is_match(&text) && !self.is_legitimate_business(sender, from_header) {
                patterns.push("Transport document scam".to_string());
                score += 75.0;
                risk_factors.push("Suspicious transport document references".to_string());
                break;
            }
        }

        // Check for legitimate order confirmations
        if self.is_legitimate_order_confirmation(subject, sender) {
            score *= 0.1; // Reduce by 90%
            risk_factors.push("Legitimate order confirmation detected".to_string());
        }

        // Check for legitimate medical institution communications
        if self.is_legitimate_medical_communication(subject, sender, &text) {
            log::debug!("Medical institution detected: sender={}, subject={}", sender, subject);
            score *= 0.1; // Reduce by 90%
            risk_factors.push("Legitimate medical institution communication detected".to_string());
        } else {
            log::debug!("Medical institution check: sender={}, not recognized as medical", sender);
        }

        // Check for brand impersonation
        if self.has_brand_impersonation(&text, sender, from_header) {
            patterns.push("Brand impersonation detected".to_string());
            score += 30.0;
        }

        // Check sender/brand alignment
        if self.has_sender_brand_mismatch(&text, sender, from_header) {
            patterns.push("Sender/brand mismatch".to_string());
            score += 25.0;
        }

        // Reduce score for legitimate businesses
        if self.is_legitimate_business(sender, from_header) {
            score *= 0.1; // Reduce by 90%
            risk_factors.push("Legitimate business sender".to_string());
        }

        // Check for subscription-related content
        if self.is_subscription_related(&text, sender) {
            score *= 0.3; // Reduce by 70%
            risk_factors.push("Subscription-related content".to_string());
        }

        let confidence = (score / 100.0).min(1.0);
        let is_fake = confidence > 0.7;

        InvoiceAnalysis {
            is_fake_invoice: is_fake,
            confidence_score: confidence,
            detected_patterns: patterns,
            risk_factors,
        }
    }

    fn has_brand_impersonation(&self, text: &str, sender: &str, _from_header: &str) -> bool {
        let brands = [
            "paypal",
            "amazon",
            "microsoft",
            "apple",
            "google",
            "adobe",
            "docusign",
            "dropbox",
            "salesforce",
            "stripe",
            "square",
            "shopify",
            "ebay",
            "walmart",
            "target",
            "bestbuy",
            "fedex",
            "ups",
            "usps",
            "dhl",
        ];

        for brand in &brands {
            if text.to_lowercase().contains(brand) && !sender.to_lowercase().contains(brand) {
                // Check if it's a legitimate service integration
                if self.is_legitimate_service_integration(text, brand, sender) {
                    continue; // Skip flagging legitimate service integrations
                }
                return true;
            }
        }

        false
    }

    fn is_legitimate_service_integration(&self, text: &str, brand: &str, sender: &str) -> bool {
        let text_lower = text.to_lowercase();

        // Check for legitimate service integration patterns
        let integrations = match brand {
            "google" => vec![
                "google pay",
                "google maps",
                "google checkout",
                "google wallet",
            ],
            "apple" => vec!["apple pay", "apple wallet"],
            "paypal" => vec!["paypal checkout", "paypal payment"],
            _ => vec![],
        };

        // If brand mention is in context of legitimate service integration
        integrations.iter().any(|integration| text_lower.contains(integration)) ||
        // Or if sender is a known legitimate business that would use these services
        self.is_known_legitimate_business(sender)
    }

    fn is_known_legitimate_business(&self, sender: &str) -> bool {
        let legitimate_businesses = [
            "pagliacci.com",
            "dominos.com",
            "pizzahut.com",
            "23andme.com",
            "ancestrydna.com",
            "ubereats.com",
            "doordash.com",
            "myheritage.com",
            "webmd.com",
            "levi.com",
            "gap.com",
            "nike.com",
            "adidas.com",
            "macys.com",
            "nordstrom.com",
            "target.com",
            "walmart.com",
            "oldnavy.com",
            "banana-republic.com",
        ];

        legitimate_businesses
            .iter()
            .any(|business| sender.contains(business))
    }

    fn has_sender_brand_mismatch(&self, text: &str, sender: &str, from_header: &str) -> bool {
        // Skip if it's a legitimate business
        if self.is_legitimate_business(sender, from_header) {
            return false;
        }

        let financial_terms = ["invoice", "bill", "payment", "charge", "account"];
        let has_financial_terms = financial_terms
            .iter()
            .any(|term| text.to_lowercase().contains(term));

        if has_financial_terms {
            // Check if sender domain looks suspicious for financial communications
            let suspicious_patterns = [
                r"@[a-z0-9]{8,15}\.[a-z]{2,4}$",
                r"@.*\.(tk|ml|ga|cf|gq|top|click)$",
                r"documento\d+@",
            ];

            for pattern in &suspicious_patterns {
                if let Ok(regex) = Regex::new(pattern) {
                    if regex.is_match(sender) {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn is_legitimate_medical_communication(&self, subject: &str, sender: &str, content: &str) -> bool {
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

        let medical_communication_patterns = [
            r"(?i)(payment.*confirmation|lab.*results|test.*results|medical.*payment|healthcare.*payment)",
            r"(?i)(patient.*portal|health.*record|appointment.*confirmation|prescription.*ready)",
            r"(?i)(billing.*statement|insurance.*claim|copay.*due|balance.*due)",
        ];

        // Check if sender is medical institution
        let is_medical_sender = medical_institutions.iter().any(|domain| 
            sender.to_lowercase().contains(domain)
        );

        // Check if content matches medical communication patterns
        let is_medical_content = medical_communication_patterns.iter().any(|pattern| {
            Regex::new(pattern).map_or(false, |re| re.is_match(content) || re.is_match(subject))
        });

        is_medical_sender && is_medical_content
    }

    fn is_legitimate_order_confirmation(&self, subject: &str, sender: &str) -> bool {
        let order_patterns = [
            r"(?i)your.*order",
            r"(?i)order.*confirmation",
            r"(?i)order.*receipt",
            r"(?i)order.*summary",
        ];

        let food_service_domains = [
            "pagliacci.com",
            "dominos.com",
            "pizzahut.com",
            "ubereats.com",
            "doordash.com",
            "grubhub.com",
            "postmates.com",
        ];

        // Check if subject matches order pattern and sender is legitimate food service
        order_patterns
            .iter()
            .any(|pattern| Regex::new(pattern).is_ok_and(|re| re.is_match(subject)))
            && food_service_domains
                .iter()
                .any(|domain| sender.contains(domain))
    }

    fn is_legitimate_business(&self, sender: &str, from_header: &str) -> bool {
        for domain in &self.legitimate_domains {
            if sender.contains(domain) || from_header.contains(domain) {
                return true;
            }
        }
        false
    }

    fn is_subscription_related(&self, text: &str, sender: &str) -> bool {
        let subscription_domains = [
            "netflix.com",
            "spotify.com",
            "hulu.com",
            "disney.com",
            "amazon.com",
            "microsoft.com",
            "adobe.com",
            "dropbox.com",
            "google.com",
            "apple.com",
        ];

        // If it's from a known subscription service
        for domain in &subscription_domains {
            if sender.contains(domain) {
                return true;
            }
        }

        // If it contains subscription language but also scam indicators, don't exclude
        let scam_indicators = [
            "overdue",
            "total amount",
            "invoice number",
            "24 hours",
            "payment required",
            "account suspended",
            "verify account",
            "update payment",
        ];
        let has_scam_language = scam_indicators
            .iter()
            .any(|&indicator| text.to_lowercase().contains(indicator));

        if has_scam_language {
            return false; // Don't exclude scams even if they mention subscriptions
        }

        // If it contains subscription language
        let mut subscription_indicators = 0;
        let subscription_patterns = [
            "subscription",
            "monthly",
            "annual",
            "recurring",
            "auto-renew",
            "billing cycle",
            "next payment",
            "plan",
            "membership",
        ];

        for pattern in &subscription_patterns {
            if text.to_lowercase().contains(pattern) {
                subscription_indicators += 1;
            }
        }

        subscription_indicators >= 2
    }
}
