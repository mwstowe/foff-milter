use super::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use regex::Regex;
use std::collections::HashMap;

pub struct SenderAlignmentAnalyzer {
    brand_patterns: HashMap<String, Vec<String>>,
    domain_regex: Regex,
}

impl Default for SenderAlignmentAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl SenderAlignmentAnalyzer {
    pub fn new() -> Self {
        let mut brand_patterns = HashMap::new();

        // Major brands and their expected domains
        brand_patterns.insert(
            "paypal".to_string(),
            vec!["paypal.com".to_string(), "paypal.me".to_string()],
        );

        brand_patterns.insert(
            "amazon".to_string(),
            vec![
                "amazon.com".to_string(),
                "amazon.co.uk".to_string(),
                "amazonses.com".to_string(),
            ],
        );

        brand_patterns.insert(
            "microsoft".to_string(),
            vec![
                "microsoft.com".to_string(),
                "outlook.com".to_string(),
                "live.com".to_string(),
            ],
        );

        brand_patterns.insert(
            "google".to_string(),
            vec![
                "google.com".to_string(),
                "gmail.com".to_string(),
                "googlemail.com".to_string(),
            ],
        );

        brand_patterns.insert(
            "norton".to_string(),
            vec![
                "norton.com".to_string(),
                "nortonlifelock.com".to_string(),
                "symantec.com".to_string(),
            ],
        );

        Self {
            brand_patterns,
            domain_regex: Regex::new(r"@([^>\s]+)").unwrap(),
        }
    }

    pub fn from_config(_config: &crate::config_loader::SenderAlignmentConfig) -> Self {
        Self::new()
    }

    fn extract_sender_info(&self, context: &MailContext) -> SenderInfo {
        let from_header = context.from_header.as_deref().unwrap_or_default();
        let sender_header = context.sender.as_deref().unwrap_or_default();
        let return_path = context
            .headers
            .get("Return-Path")
            .cloned()
            .unwrap_or_default();

        SenderInfo {
            from_domain: self.extract_domain(from_header),
            sender_domain: self.extract_domain(sender_header),
            return_path_domain: self.extract_domain(&return_path),
            from_display_name: self.extract_display_name(from_header),
        }
    }

    fn extract_email_from_header(&self, header: &str) -> Option<String> {
        // Use the same email extraction logic as the milter module
        crate::milter::extract_email_from_header(header)
    }

    fn domain_exists(&self, domain: &str) -> bool {
        if domain.is_empty() || domain == "unknown" {
            return false;
        }

        // Skip check for legitimate email services to avoid false positives
        if self.is_legitimate_email_service(domain) {
            return true;
        }

        // Handle complex CNAME-based domains (Adobe Campaign, etc.)
        if self.is_complex_cname_domain(domain) {
            return true; // Assume legitimate for complex marketing platforms
        }

        // Use std::net for synchronous DNS lookup
        use std::net::ToSocketAddrs;

        // Try to resolve the domain
        match format!("{}:80", domain).to_socket_addrs() {
            Ok(mut addrs) => addrs.next().is_some(),
            Err(_) => {
                // Check for obviously suspicious patterns
                let suspicious_patterns = [
                    "automated",
                    "outreach",
                    "pro",
                    "bulk",
                    "mass",
                    "spam",
                    "marketing",
                    "promo",
                    "blast",
                    "campaign",
                    "mailer",
                ];

                let domain_lower = domain.to_lowercase();
                let has_suspicious_pattern = suspicious_patterns
                    .iter()
                    .any(|pattern| domain_lower.contains(pattern));

                // Only flag as non-existent if it has suspicious patterns AND doesn't resolve
                if has_suspicious_pattern {
                    false // Flag as non-existent
                } else {
                    true // Assume exists for other domains to avoid false positives
                }
            }
        }
    }

    fn is_complex_cname_domain(&self, domain: &str) -> bool {
        let cname_patterns = [
            ".cname.campaign.adobe.com",
            ".cname.cjm.adobe.com",
            ".campaign.adobe.com",
            ".cjm.adobe.com",
            ".exacttarget.com",
            ".salesforce.com",
            ".pardot.com",
            ".hubspot.com",
            ".marketo.com",
            ".eloqua.com",
        ];

        cname_patterns
            .iter()
            .any(|pattern| domain.ends_with(pattern))
    }

    fn is_legitimate_email_service(&self, domain: &str) -> bool {
        let legitimate_services = [
            "sendgrid.net",
            "mailgun.org",
            "amazonses.com",
            "mailchimp.com",
            "constantcontact.com",
            "campaignmonitor.com",
            "aweber.com",
            "getresponse.com",
            "convertkit.com",
            "activecampaign.com",
            "drip.com",
            "klaviyo.com",
            "klaviyodns.com",
            "sendinblue.com",
            "postmarkapp.com",
            "sparkpost.com",
            "sparkpostmail.com",
            "mandrill.com",
            "cmd.emsend1.com",
            "acems2.com",
            "mandrillapp.com",
            "mailjet.com",
            "concurcompleat.com",
            "oracleemaildelivery.com",
            "bounce.concurcompleat.com",
            "narvar.com",
            "tracking.domain-track.prod20.narvar.com",
            "spmailtechno.com",
            "gmail.com",                  // For forwarded emails
            "emails.pitneybowes.com",     // Pitney Bowes email service
            "mail.arrived.com",           // Arrived email service
            "mcdlv.net",                  // MailChimp delivery network
            "wdc02.mcdlv.net",            // MailChimp WDC02 delivery
            "hb.d.mailin.fr",             // Mailjet/Sendinblue ESP
            "mailin.fr",                  // Sendinblue
            "bounce.e.rejuvenation.com",  // Rejuvenation ESP
            "bounce.e.onestopplus.com",   // OneStopPlus ESP
            "charmtracker.com",           // Healthcare EHR
            "mailerehr.charmtracker.com", // CharmTracker EHR
        ];

        legitimate_services
            .iter()
            .any(|service| domain.contains(service))
    }

    fn is_valid_domain_format(&self, domain: &str) -> bool {
        // Basic domain format validation
        if domain.is_empty() || domain == "unknown" {
            return false;
        }

        // Must contain at least one dot and valid TLD
        let domain_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$").unwrap();
        domain_regex.is_match(domain)
    }

    fn analyze_display_name_consistency(&self, from_header: &str) -> (i32, Vec<String>) {
        let mut score = 0;
        let mut evidence = Vec::new();

        // Extract display name and email parts
        if let Some(angle_start) = from_header.rfind('<') {
            let display_part = from_header[..angle_start].trim().trim_matches('"');
            let email_part = &from_header[angle_start + 1..].trim_end_matches('>');

            // Check for suspicious display name patterns
            let suspicious_chars = ['@', '<', '>', '[', ']', '{', '}', '|', '\\'];
            if display_part.chars().any(|c| suspicious_chars.contains(&c)) {
                // Skip if it's a legitimate business format like "Business Name (email@domain.com)"
                let business_contact_pattern =
                    regex::Regex::new(r"^[^<>]+\s*\([^)]+@[^)]+\)$").unwrap();
                if !business_contact_pattern.is_match(display_part) {
                    score += 20;
                    evidence.push("Display name contains suspicious characters".to_string());
                }
            }

            // Disabled: overly broad detection that flags legitimate business names
            // TODO: Replace with more specific suspicious pattern detection
            /*
            let suspicious_pattern = regex::Regex::new(r"[!@#$%^&*()_+={}|\[\]\\:;\"'<>?,./]{5,}|[0-9]{8,}").unwrap();
            if suspicious_pattern.is_match(display_part) {
                score += 15;
                evidence.push("Display name contains excessive special characters".to_string());
            }
            */

            // Check for domain mismatch in display name
            if display_part.contains('@') && !display_part.contains(email_part) {
                // Skip for legitimate NetSuite business invoices
                let is_netsuite_invoice = email_part.contains("sent-via.netsuite.com")
                    && display_part.contains('(')
                    && display_part.contains('@')
                    && display_part.contains(')');

                if !is_netsuite_invoice {
                    score += 25;
                    evidence.push("Display name contains different email domain".to_string());
                }
            }

            // Check for brand impersonation patterns (skip social media links)
            let brand_keywords = [
                "paypal",
                "amazon",
                "microsoft",
                "google",
                "apple",
                "facebook",
                "bank",
                "citi",
                "citibank",
                "chase",
                "wellsfargo",
                "wells fargo",
                "bankofamerica",
                "bank of america",
                "jpmorgan",
                "discover",
            ];
            let display_lower = display_part.to_lowercase();
            let email_lower = email_part.to_lowercase();

            // Skip brand detection if this appears to be social media links or footers
            let is_social_media_context = display_lower.contains("facebook.com") 
                || display_lower.contains("twitter.com")
                || display_lower.contains("instagram.com")
                || display_lower.contains("linkedin.com")
                || display_lower.contains("plus.google.com")
                || display_lower.contains("youtube.com")
                || display_lower.contains("google.com/maps")
                || display_lower.contains("googlemail.com")
                || display_lower.contains("gmail.com");

            if !is_social_media_context {
                for brand in &brand_keywords {
                    if display_lower.contains(brand) && !email_lower.contains(brand) {
                        score += 30;
                        evidence.push(format!(
                            "Display name claims '{}' but email domain doesn't match",
                            brand
                        ));
                        break;
                    }
                }
            }
        }

        (score, evidence)
    }

    fn extract_domain(&self, header: &str) -> String {
        // Try to extract from angle brackets first (most reliable)
        if let Some(angle_match) = Regex::new(r"<[^<>]*@([^<>\s]+)>").unwrap().captures(header) {
            if let Some(domain) = angle_match.get(1) {
                return domain.as_str().trim_end_matches('>').to_string();
            }
        }

        // Fallback to general @ pattern
        if let Some(cap) = self.domain_regex.captures(header) {
            if let Some(domain) = cap.get(1) {
                let domain_str = domain.as_str().trim_end_matches('>').trim_end_matches(')');
                return domain_str.to_string();
            }
        }
        "unknown".to_string()
    }

    fn extract_display_name(&self, from_header: &str) -> String {
        if let Some(lt_pos) = from_header.find('<') {
            from_header[..lt_pos].trim().trim_matches('"').to_string()
        } else {
            "".to_string()
        }
    }

    fn analyze_sender_name_spoofing(
        &self,
        _sender_info: &SenderInfo,
        context: &MailContext,
    ) -> Vec<String> {
        let mut issues = Vec::new();

        let from_header = context.from_header.as_deref().unwrap_or("");

        // Extract the local part of the email (before @)
        let email_local = if let Some(email_start) = from_header.rfind('<') {
            let email_part = &from_header[email_start + 1..].trim_end_matches('>');
            email_part.split('@').next().unwrap_or("").to_lowercase()
        } else {
            from_header.split('@').next().unwrap_or("").to_lowercase()
        };

        // Check for random keyword combinations (3+ unrelated words)
        let random_keywords = [
            "toyota", "mercury", "sedge", "red", "baseball", "homerun", "now", "apple", "banana",
            "car", "house", "blue", "green", "fast", "slow", "big", "small", "hot", "cold", "new",
            "old", "good", "bad",
        ];

        let mut keyword_count = 0;
        for keyword in &random_keywords {
            if email_local.contains(keyword) {
                keyword_count += 1;
            }
        }

        // If 3+ random keywords in sender name, it's likely spoofing
        if keyword_count >= 3 {
            issues.push(format!(
                "Sender name contains {} random keywords: suspicious spoofing pattern",
                keyword_count
            ));
        }

        // Check for excessive length with mixed words (likely random generation)
        if email_local.len() > 25 && keyword_count >= 2 {
            issues.push("Excessively long sender name with mixed keywords".to_string());
        }

        issues
    }

    fn analyze_infrastructure_mismatch(
        &self,
        sender_info: &SenderInfo,
        context: &MailContext,
    ) -> Vec<String> {
        let mut issues = Vec::new();

        log::debug!(
            "Infrastructure validation - checking sender: {}",
            sender_info.from_domain
        );

        // Major brands that should have proper corporate infrastructure
        const MAJOR_BRANDS: &[(&str, &[&str])] = &[
            ("walmart", &["walmart.com", "wal-mart.com"]),
            ("amazon", &["amazon.com", "amazonses.com", "amazon.co.uk"]),
            ("target", &["target.com"]),
            ("bestbuy", &["bestbuy.com"]),
            ("costco", &["costco.com"]),
            ("homedepot", &["homedepot.com"]),
            ("apple", &["apple.com", "icloud.com"]),
            ("microsoft", &["microsoft.com", "outlook.com"]),
            ("google", &["google.com", "gmail.com"]),
        ];

        // Suspicious infrastructure patterns
        const SUSPICIOUS_INFRASTRUCTURE: &[&str] = &[
            r"cs-\d+-default\..*\.internal",
            r".*-\d+-default\..*\.c\..*\.internal",
            r"pod-id.*\.internal",
            r"\.internal$",
            r"userid 0",
        ];

        // Check if sender claims to be from a major brand
        for (brand, expected_domains) in MAJOR_BRANDS {
            let claims_brand = sender_info.from_domain.to_lowercase().contains(brand)
                || sender_info.from_display_name.to_lowercase().contains(brand);

            if claims_brand {
                log::debug!("Found brand claim: {}", brand);

                // Check if domain is actually legitimate for this brand
                let is_legitimate_domain = expected_domains
                    .iter()
                    .any(|domain| sender_info.from_domain.to_lowercase().contains(domain));

                if is_legitimate_domain {
                    log::debug!(
                        "Domain appears legitimate for {}, checking infrastructure",
                        brand
                    );

                    // Check received headers for suspicious infrastructure
                    for (header_name, header_value) in &context.headers {
                        if header_name.to_lowercase() == "received" {
                            log::debug!("Checking received header: {}", header_value);

                            for pattern in SUSPICIOUS_INFRASTRUCTURE {
                                if regex::Regex::new(pattern).unwrap().is_match(header_value) {
                                    log::info!(
                                        "INFRASTRUCTURE MISMATCH DETECTED: {} using {}",
                                        brand.to_uppercase(),
                                        pattern
                                    );
                                    issues.push(format!(
                                        "Major brand {} using suspicious infrastructure: {}",
                                        brand.to_uppercase(),
                                        pattern
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        log::debug!("Infrastructure validation found {} issues", issues.len());
        issues
    }

    fn analyze_brand_impersonation(
        &self,
        sender_info: &SenderInfo,
        context: &MailContext,
    ) -> Vec<String> {
        let mut issues = Vec::new();
        let body = context.body.as_deref().unwrap_or("");
        let subject = context
            .headers
            .get("Subject")
            .map(|s| s.as_str())
            .unwrap_or("");

        // Skip brand impersonation detection for job-related content
        if self.is_job_related_content(subject, body) {
            return issues;
        }

        // Check if email body contains social media links (indicates legitimate business communication)
        let is_social_media_context = body.to_lowercase().contains("facebook.com") 
            || body.to_lowercase().contains("twitter.com")
            || body.to_lowercase().contains("instagram.com")
            || body.to_lowercase().contains("linkedin.com")
            || body.to_lowercase().contains("plus.google.com")
            || body.to_lowercase().contains("youtube.com")
            || body.to_lowercase().contains("pinterest.com")
            || body.to_lowercase().contains("google.com/maps")
            || body.to_lowercase().contains("googlemail.com")
            || body.to_lowercase().contains("gmail.com");

        // Skip brand detection if this appears to be legitimate business communication with social media
        if is_social_media_context {
            return issues;
        }

        // Enhanced brand domain validation with stricter checking
        let enhanced_brands = [
            ("spotify", vec!["spotify.com", "spotifymail.com"]),
            ("nhk", vec!["nhk.or.jp", "nhk.go.jp"]),
            ("apple", vec!["apple.com", "icloud.com"]),
            ("google", vec!["google.com", "gmail.com", "googlemail.com"]),
            (
                "microsoft",
                vec!["microsoft.com", "outlook.com", "hotmail.com"],
            ),
            ("amazon", vec!["amazon.com", "amazonses.com"]),
            ("paypal", vec!["paypal.com", "paypal.me"]),
        ];

        // Check enhanced brand patterns first (only in display name and subject for precision)
        for (brand, valid_domains) in &enhanced_brands {
            let brand_mentioned = sender_info.from_display_name.to_lowercase().contains(brand)
                || subject.to_lowercase().contains(brand);

            if brand_mentioned {
                // Skip if this is a legitimate business domain containing the brand name
                let is_legitimate_business = sender_info.from_domain.contains(brand)
                    || sender_info.from_domain.contains(&format!("{}.", brand))
                    || sender_info.from_domain.ends_with(&format!("{}.com", brand));

                if !is_legitimate_business {
                    let domain_valid = valid_domains.iter().any(|domain| {
                        sender_info.from_domain.contains(domain)
                            || sender_info.sender_domain.contains(domain)
                            || sender_info.return_path_domain.contains(domain)
                    });

                    if !domain_valid {
                        issues.push(format!(
                            "Major brand impersonation: {} from invalid domain {}",
                            brand, sender_info.from_domain
                        ));
                    }
                }
            }
        }

        // Special handling for Japanese brands (NHK detection)
        if sender_info.from_display_name.to_lowercase().contains("nhk")
            && !sender_info.from_domain.contains("nhk.or.jp")
            && !sender_info.from_domain.contains("nhk.go.jp")
        {
            issues.push(format!(
                "Japanese brand impersonation: NHK from non-Japanese domain {}",
                sender_info.from_domain
            ));
        }

        // Check for random sender IDs
        if let Some(from_header) =
            crate::features::get_header_case_insensitive(&context.headers, "from")
        {
            if let Some(email_part) = from_header.split('<').nth(1) {
                if let Some(local_part) = email_part.split('@').next() {
                    if local_part.len() >= 8
                        && local_part.chars().any(|c| c.is_ascii_uppercase())
                        && local_part.chars().any(|c| c.is_ascii_lowercase())
                        && local_part.chars().any(|c| c.is_ascii_digit())
                        && local_part.chars().all(|c| c.is_ascii_alphanumeric())
                    {
                        issues.push(format!("Random sender ID detected: {}", local_part));
                    }
                }
            }
        }

        // Check for suspicious administrative domains
        let admin_patterns = ["admin-", "support-", "service-", "account-", "billing-"];
        if admin_patterns
            .iter()
            .any(|pattern| sender_info.from_domain.starts_with(pattern))
        {
            issues.push(format!(
                "Suspicious administrative domain: {}",
                sender_info.from_domain
            ));
        }

        // Original brand pattern checking (for backward compatibility)
        for (brand, legitimate_domains) in &self.brand_patterns {
            // Check if brand is mentioned in display name, subject, or body
            let brand_mentioned = sender_info.from_display_name.to_lowercase().contains(brand)
                || subject.to_lowercase().contains(brand)
                || body.to_lowercase().contains(brand);

            if brand_mentioned {
                // Skip AWS infrastructure references (not actual brand impersonation)
                if brand == "amazon"
                    && self.is_aws_infrastructure_reference(body)
                    && !sender_info
                        .from_display_name
                        .to_lowercase()
                        .contains("amazon")
                {
                    continue;
                }

                // Check if sender domain is legitimate for this brand
                let domain_legitimate = legitimate_domains.iter().any(|domain| {
                    sender_info.from_domain.contains(domain)
                        || sender_info.sender_domain.contains(domain)
                        || sender_info.return_path_domain.contains(domain)
                });

                if !domain_legitimate {
                    issues.push(format!(
                        "Brand '{}' mentioned but sender domain '{}' not legitimate",
                        brand, sender_info.from_domain
                    ));
                }
            }
        }

        issues
    }

    fn analyze_domain_consistency(&self, sender_info: &SenderInfo) -> Vec<String> {
        let mut issues = Vec::new();

        // Check if From and Sender domains are consistent (allow legitimate email services)
        if !sender_info.sender_domain.is_empty()
            && sender_info.sender_domain != "unknown"
            && !self.domains_related(&sender_info.from_domain, &sender_info.sender_domain)
            && !self.is_legitimate_email_service(&sender_info.sender_domain)
        {
            issues.push(format!(
                "From domain '{}' doesn't match Sender domain '{}'",
                sender_info.from_domain, sender_info.sender_domain
            ));
        }

        // Check Return-Path alignment
        if !sender_info.return_path_domain.is_empty()
            && sender_info.return_path_domain != "unknown"
            && !self.domains_related(&sender_info.from_domain, &sender_info.return_path_domain)
        {
            issues.push(format!(
                "From domain '{}' doesn't align with Return-Path domain '{}'",
                sender_info.from_domain, sender_info.return_path_domain
            ));
        }

        issues
    }

    fn is_legitimate_business(&self, sender_info: &SenderInfo) -> bool {
        let legitimate_businesses = [
            "costco.com",
            "pitneybowes.com",
            "arrived.com",
            "cults3d.com",
            "amazon.com",
            "microsoft.com",
            "google.com",
            "apple.com",
            "walmart.com",
            "target.com",
            "homedepot.com",
            "lowes.com",
            "bestbuy.com",
            "macys.com",
            "nordstrom.com",
            "humblebundle.com",
            "bedjet.com",
            "ladyyum.com",
            "ikea.us",
            "capitalone.com",
            "capitaloneshopping.com",
            "mailer.humblebundle.com",
            "poshmark.com", // Marketplace platform
            "ebay.com",
            "etsy.com",
            "mercari.com",
            "medium.com", // Publishing platform
            "substack.com",
            "eflorist.com", // Florist platform
            // Medical platforms
            "charmtracker.com", // AceMed medical platform
            "athenahealth.com",
            "epic.com",
            "cerner.com",
            // E-commerce platforms
            "narvar.com",       // Order tracking platform
            "shipstation.com",  // Shipping platform
            "aftership.com",    // Package tracking
            "route.com",        // Delivery tracking
            "trackingmore.com", // Multi-carrier tracking
            // Health/fitness platforms
            "withings.com",     // Health devices
            "fitbit.com",       // Fitness tracking
            "garmin.com",       // Sports/health devices
            "oura.com",         // Health rings
            "myfitnesspal.com", // Nutrition tracking
            // Specific failing domains
            "domain-track.prod20.narvar.com", // Duluth tracking
            "email.withings.com",             // Withings health
        ];

        // Check the full domain for business names (handles complex domains like Adobe Campaign)
        let full_domain = &sender_info.from_domain;
        let from_root = self.extract_root_domain(&sender_info.from_domain);

        legitimate_businesses
            .iter()
            .any(|business| full_domain.contains(business) || from_root.contains(business))
    }

    fn is_corporate_partnership(&self, display_name: &str, sender_domain: &str) -> bool {
        let display_lower = display_name.to_lowercase();
        let domain_lower = sender_domain.to_lowercase();

        // Corporate benefits partnerships
        let partnerships = [
            ("amazon", vec!["fidelity.com", "vanguard.com"]),
            ("microsoft", vec!["fidelity.com", "schwab.com"]),
            ("google", vec!["fidelity.com", "vanguard.com"]),
            ("apple", vec!["fidelity.com", "vanguard.com"]),
        ];

        for (company, partners) in &partnerships {
            if display_lower.contains(company) {
                return partners
                    .iter()
                    .any(|partner| domain_lower.contains(partner));
            }
        }

        false
    }

    fn is_aws_infrastructure_reference(&self, content: &str) -> bool {
        let aws_patterns = ["amazonaws.com", "cloudfront.net", "s3.amazonaws.com", "s3-"];

        aws_patterns.iter().any(|pattern| content.contains(pattern))
    }

    fn extract_root_domain(&self, domain: &str) -> String {
        if domain.is_empty() || domain == "unknown" {
            return domain.to_string();
        }

        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            domain.to_string()
        }
    }

    fn domains_related(&self, domain1: &str, domain2: &str) -> bool {
        // Normalize domains for case-insensitive comparison
        let domain1_lower = domain1.to_lowercase();
        let domain2_lower = domain2.to_lowercase();

        // Same domain (case-insensitive)
        if domain1_lower == domain2_lower {
            return true;
        }

        // Extract root domains and compare (handles subdomains)
        let root1 = self.extract_root_domain(&domain1_lower);
        let root2 = self.extract_root_domain(&domain2_lower);

        if root1 == root2 {
            return true;
        }

        // Known legitimate relationships
        let legitimate_pairs = [
            ("amazon.com", "amazonses.com"),
            ("amazon.com", "bounces.amazon.com"),
            ("primevideo.com", "amazon.com"),
            ("primevideo.com", "bounces.amazon.com"),
            ("primevideo.com", "amazonses.com"),
            ("microsoft.com", "outlook.com"),
            ("google.com", "gmail.com"),
        ];

        for (d1, d2) in &legitimate_pairs {
            if (domain1.contains(d1) && domain2.contains(d2))
                || (domain1.contains(d2) && domain2.contains(d1))
            {
                return true;
            }
        }

        // Legitimate payment processors - don't flag as mismatched
        let payment_processors = [
            "pestconnect.com",
            "stripe.com",
            "paypal.com",
            "square.com",
            "quickbooks.com",
            "invoicecloud.com",
            "billpay.com",
            "autopay.com",
            "paymi.com",
            "epay.com",
        ];

        for processor in &payment_processors {
            if domain1.contains(processor) || domain2.contains(processor) {
                return true;
            }
        }

        false
    }

    fn analyze_display_name_spoofing(&self, sender_info: &SenderInfo) -> Vec<String> {
        let mut issues = Vec::new();
        let display_name = &sender_info.from_display_name.to_lowercase();

        // Check for suspicious display name patterns
        if display_name.contains("noreply") && !sender_info.from_domain.contains("noreply") {
            // This is often legitimate
        } else if display_name.contains("support")
            && !sender_info.from_domain.contains("support")
            && !self.is_known_support_domain(&sender_info.from_domain)
            && !self.is_legitimate_support_pattern(
                &sender_info.from_display_name,
                &sender_info.from_domain,
            )
        {
            issues.push("Display name suggests support but domain doesn't match".to_string());
        }

        // Check for Unicode spoofing
        if display_name.chars().any(|c| c as u32 > 127) {
            issues.push(
                "Display name contains non-ASCII characters (potential spoofing)".to_string(),
            );
        }

        issues
    }

    fn is_known_support_domain(&self, domain: &str) -> bool {
        let support_domains = [
            "zendesk.com",
            "freshdesk.com",
            "helpscout.net",
            "intercom.io",
            "salesforce.com",
            "resmed.com",
            // Major legitimate businesses that commonly use "support" in display names
            "namecheap.com",
            "godaddy.com",
            "hostgator.com",
            "bluehost.com",
            "dreamhost.com",
            "siteground.com",
            "digitalocean.com",
            "linode.com",
            "vultr.com",
            "cloudflare.com",
            "amazon.com",
            "microsoft.com",
            "google.com",
            "apple.com",
            "paypal.com",
            "stripe.com",
            "square.com",
            "shopify.com",
            "woocommerce.com",
            "wordpress.com",
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            "atlassian.com",
            "slack.com",
            "discord.com",
            "zoom.us",
            "dropbox.com",
            "box.com",
            "adobe.com",
            "autodesk.com",
            "salesforce.com",
            "hubspot.com",
            "mailchimp.com",
            "constantcontact.com",
            "sendgrid.net",
            "twilio.com",
        ];
        support_domains.iter().any(|d| domain.contains(d))
    }

    /// Check if this is a legitimate support pattern (e.g., "Company Support" from company.com)
    fn is_legitimate_support_pattern(&self, display_name: &str, domain: &str) -> bool {
        let display_lower = display_name.to_lowercase();
        let domain_lower = domain.to_lowercase();

        // Extract company name from domain (e.g., "namecheap" from "namecheap.com")
        let domain_parts: Vec<&str> = domain_lower.split('.').collect();
        if let Some(company_name) = domain_parts.first() {
            // Check if display name contains the company name + support
            // e.g., "Namecheap Support" from namecheap.com
            if display_lower.contains(company_name) && display_lower.contains("support") {
                return true;
            }

            // Check for common legitimate patterns
            let legitimate_patterns = [
                &format!("{} support", company_name),
                &format!("support {}", company_name),
                &format!("{} customer support", company_name),
                &format!("{} technical support", company_name),
                &format!("{} help", company_name),
                &format!("{} team", company_name),
            ];

            for pattern in &legitimate_patterns {
                if display_lower.contains(pattern.as_str()) {
                    return true;
                }
            }
        }

        false
    }

    fn detect_professional_credentials(&self, sender: &str) -> bool {
        const MEDICAL_CREDENTIALS: &[&str] = &[
            "dr.", "dr ", "md", "phd", "dds", "dvm", "pharmd", "rn", "np",
        ];

        const MEDICAL_DOMAINS: &[&str] = &[
            ".edu", "medical", "health", "clinic", "hospital", "research",
        ];

        let sender_lower = sender.to_lowercase();

        // Check for medical credentials in sender name
        let has_credentials = MEDICAL_CREDENTIALS
            .iter()
            .any(|cred| sender_lower.contains(cred));

        // Check for medical/research domains
        let has_medical_domain = MEDICAL_DOMAINS
            .iter()
            .any(|domain| sender_lower.contains(domain));

        has_credentials || has_medical_domain
    }

    fn detect_legitimate_organization(&self, domain: &str) -> bool {
        const NONPROFIT_ORGS: &[&str] = &[
            "eff.org",
            "aclu.org",
            "amnesty.org",
            "redcross.org",
            "unitedway.org",
            "goodwill.org",
            "salvation",
            "habitat.org",
        ];

        const HEALTHCARE_PROVIDERS: &[&str] = &[
            "zoomcare.com",
            "kaiser",
            "providence",
            "swedish.org",
            "virginia",
            "mayo.edu",
            "cleveland",
            "johns",
        ];

        const MAJOR_BRANDS: &[&str] = &[
            "apple.com",
            "applecard.apple",
            "notification.capitalone.com",
            "capitaloneshopping.com",
            "ikea.us",
            "bedjet.com",
            "ladyyum.com",
            "humblebundle.com",
            "mailer.humblebundle.com",
        ];

        // Check for .org domains (general nonprofit indicator)
        if domain.ends_with(".org") {
            return true;
        }

        // Check specific known organizations
        NONPROFIT_ORGS.iter().any(|org| domain.contains(org))
            || HEALTHCARE_PROVIDERS
                .iter()
                .any(|provider| domain.contains(provider))
            || MAJOR_BRANDS.iter().any(|brand| domain.contains(brand))
    }

    fn detect_suspicious_brand_impersonation(
        &self,
        sender: &str,
        domain: &str,
    ) -> (i32, Vec<String>) {
        const SUSPICIOUS_PATTERNS: &[&str] =
            &["no-replay", "no-repley", "noreplay", "no_reply", "norepy"];

        const MAJOR_BRANDS: &[&str] = &[
            "walmart",
            "amazon",
            "apple",
            "microsoft",
            "google",
            "facebook",
            "paypal",
            "ebay",
            "target",
            "costco",
            "bestbuy",
        ];

        let sender_lower = sender.to_lowercase();
        let domain_lower = domain.to_lowercase();

        // Exclude legitimate Apple domains from brand impersonation detection
        if domain_lower.contains("apple.com") || domain_lower.contains("applecard.apple") {
            return (0, vec![]);
        }

        // Exclude legitimate PayPal domains from brand impersonation detection
        if domain_lower.contains("paypal.com") {
            return (0, vec![]);
        }

        log::debug!(
            "Brand impersonation check - sender: '{}', domain: '{}'",
            sender,
            domain
        );

        // Check for suspicious sender patterns
        let has_suspicious_pattern = SUSPICIOUS_PATTERNS
            .iter()
            .any(|pattern| sender_lower.contains(pattern));

        // Check if claiming to be major brand
        let claims_major_brand = MAJOR_BRANDS
            .iter()
            .any(|brand| domain_lower.contains(brand));

        log::debug!(
            "Suspicious pattern: {}, Major brand: {}",
            has_suspicious_pattern,
            claims_major_brand
        );

        if has_suspicious_pattern && claims_major_brand {
            log::info!("BRAND IMPERSONATION DETECTED: {} + {}", sender, domain);
            (
                300,
                vec!["Suspicious brand impersonation pattern detected".to_string()],
            )
        } else if has_suspicious_pattern {
            (150, vec!["Suspicious sender pattern detected".to_string()])
        } else {
            (0, vec![])
        }
    }
}

#[derive(Debug)]
struct SenderInfo {
    from_domain: String,
    sender_domain: String,
    return_path_domain: String,
    from_display_name: String,
}

impl FeatureExtractor for SenderAlignmentAnalyzer {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let sender_info = self.extract_sender_info(context);
        let mut evidence = Vec::new();
        let mut score = 0;

        // Check for invalid or missing domains (very high score) - only critical headers
        // From header MUST have a valid domain
        if sender_info.from_domain == "unknown" || sender_info.from_domain.is_empty() {
            // Only flag if we actually have a from_header but failed to extract domain
            if let Some(from_header) = context.from_header.as_deref() {
                if !from_header.is_empty() {
                    score += 120;
                    evidence.push("From header has invalid or missing domain".to_string());
                }
            }
        } else if !self.is_valid_domain_format(&sender_info.from_domain) {
            score += 100;
            evidence.push(format!(
                "From header has malformed domain: {}",
                sender_info.from_domain
            ));
        } else if !self.domain_exists(&sender_info.from_domain) {
            score += 110;
            evidence.push(format!(
                "From domain does not exist: {}",
                sender_info.from_domain
            ));
        }

        // Return-Path should also have a valid domain (but less critical)
        if !sender_info.return_path_domain.is_empty()
            && sender_info.return_path_domain != "unknown"
            && !self.is_valid_domain_format(&sender_info.return_path_domain)
        {
            score += 80;
            evidence.push(format!(
                "Return-Path header has malformed domain: {}",
                sender_info.return_path_domain
            ));
        }

        // Check major brand impersonation (sender claiming to BE the brand)
        let brand_patterns = [
            ("ebay", vec!["ebay.com", "ebay.co.uk", "ebay.de"]),
            ("fedex", vec!["fedex.com", "fedex.co.uk"]),
            ("ups", vec!["ups.com"]),
            ("dhl", vec!["dhl.com"]),
            ("starbucks", vec!["starbucks.com"]),
            ("costco", vec!["costco.com", "costco.ca"]),
            ("walmart", vec!["walmart.com"]),
            ("target", vec!["target.com"]),
        ];

        let from_header = context.from_header.as_deref().unwrap_or("");
        let sender_domain = context.sender.as_deref().unwrap_or("");

        for (brand, official_domains) in &brand_patterns {
            // Only trigger if sender claims to BE the brand (not just mentioning it)
            let brand_claim_patterns = [
                format!("^{}", brand),     // Starts with brand name
                format!("{} -", brand),    // "eBay -" format
                format!("^\"{}\"", brand), // Quoted brand name
            ];

            let claims_brand = brand_claim_patterns.iter().any(|pattern| {
                regex::Regex::new(&format!("(?i){}", pattern))
                    .unwrap()
                    .is_match(from_header)
            });

            if claims_brand {
                let is_official = official_domains
                    .iter()
                    .any(|domain| sender_domain.contains(domain) || from_header.contains(domain));
                if !is_official {
                    score += 75;
                    evidence.push(format!(
                        "Brand impersonation: Claims {} from non-official domain",
                        brand.to_uppercase()
                    ));
                    break;
                }
            }
        }

        // Check sender mismatch (Gmail claiming business groups)
        if let Some(sender) = &context.sender {
            if sender.contains("@gmail.com") {
                if let Some(raw_headers) =
                    crate::features::get_header_case_insensitive(&context.headers, "raw")
                {
                    if raw_headers.contains("@wntwhitelabelsolutions.com")
                        || raw_headers.contains("business")
                        || raw_headers.contains("group")
                    {
                        score += 30;
                        evidence
                            .push("Gmail sender claiming business/group affiliation".to_string());
                    }
                }
            }
        }

        // Check suspicious sender patterns (Brand@Non-Brand-Domain format)
        let suspicious_sender_patterns =
            [r"^(starbucks|costco|walmart|target|amazon|apple|microsoft)@.*\.(com|net|org)$"];

        for pattern in &suspicious_sender_patterns {
            let regex = Regex::new(&format!("(?i){}", pattern)).unwrap();
            if regex.is_match(from_header) {
                // Check if it's NOT from official domain
                let is_official = [
                    "starbucks.com",
                    "costco.com",
                    "walmart.com",
                    "target.com",
                    "amazon.com",
                    "apple.com",
                    "microsoft.com",
                ]
                .iter()
                .any(|domain| from_header.contains(domain));
                if !is_official {
                    score += 30;
                    evidence.push("Suspicious sender format detected".to_string());
                    break;
                }
            }
        }

        // Check suspicious domain patterns (avoid legitimate business subdomains)
        let suspicious_domain_patterns = [
            r"mystery\.box\.",
            r"[a-z]+box[0-9]+@", // Only match in email addresses
            r"dinisunnet\.com",  // Specific suspicious domain
        ];

        for pattern in &suspicious_domain_patterns {
            let regex = Regex::new(&format!("(?i){}", pattern)).unwrap();
            if regex.is_match(sender_domain) || regex.is_match(from_header) {
                score += 20;
                evidence.push("Suspicious domain pattern detected".to_string());
                break;
            }
        }

        // Check authentication failures combined with brand claims and giveaway language
        if let Some(raw_headers) =
            crate::features::get_header_case_insensitive(&context.headers, "raw")
        {
            let dkim = context.dkim_verification_readonly();
            let has_auth_failure = matches!(
                dkim.auth_status,
                crate::dkim_verification::DkimAuthStatus::Fail(_)
            ) || raw_headers.contains("spf=fail");
            let claims_major_brand = [
                "ebay",
                "fedex",
                "ups",
                "dhl",
                "amazon",
                "paypal",
                "microsoft",
                "apple",
                "starbucks",
                "costco",
                "walmart",
                "target",
            ]
            .iter()
            .any(|brand| from_header.to_lowercase().contains(brand));
            let has_giveaway_language = ["giveaway", "claim", "prize", "winner", "gift", "contest"]
                .iter()
                .any(|word| {
                    from_header.to_lowercase().contains(word)
                        || context
                            .subject
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(word)
                });

            if has_auth_failure && claims_major_brand && has_giveaway_language {
                score += 40;
                evidence.push(
                    "Authentication failure with brand claim and giveaway language".to_string(),
                );
            } else if has_auth_failure && claims_major_brand {
                score += 35;
                evidence.push("Authentication failure combined with major brand claim".to_string());
            }
        }

        // Enhanced display name consistency analysis
        if let Some(from_header) = &context.from_header {
            let display_name_score = self.analyze_display_name_consistency(from_header);
            score += display_name_score.0;
            evidence.extend(display_name_score.1);
        }

        // Enhanced authentication failure detection
        if let Some(raw_headers) =
            crate::features::get_header_case_insensitive(&context.headers, "raw")
        {
            let mut auth_failures = Vec::new();
            let mut auth_score = 0;

            // Check individual authentication failures using unified API
            let dkim = context.dkim_verification_readonly();
            if matches!(
                dkim.auth_status,
                crate::dkim_verification::DkimAuthStatus::Fail(_)
            ) {
                auth_score += 15;
                auth_failures.push("DKIM");
            }
            if raw_headers.contains("spf=fail") || raw_headers.contains("spf=none") {
                auth_score += 20;
                auth_failures.push("SPF");
            }
            if raw_headers.contains("dmarc=fail") {
                auth_score += 25;
                auth_failures.push("DMARC");
            }

            // Bonus for multiple failures
            if auth_failures.len() > 1 {
                auth_score += 15;
                evidence.push(format!(
                    "Multiple authentication failures: {}",
                    auth_failures.join(" + ")
                ));
            } else if !auth_failures.is_empty() {
                evidence.push(format!("{} authentication failure", auth_failures[0]));
            }

            score += auth_score;
        }

        // Check Reply-To mismatch
        if let Some(reply_to_header) =
            crate::features::get_header_case_insensitive(&context.headers, "reply-to")
        {
            if let Some(reply_to_email) = self.extract_email_from_header(reply_to_header) {
                // Get From email for comparison
                if let Some(from_email) = self
                    .extract_email_from_header(context.from_header.as_deref().unwrap_or_default())
                {
                    if from_email != reply_to_email {
                        // Check if this is a legitimate ESP practice (same root domain)
                        let from_domain = self.extract_domain(&from_email);
                        let reply_to_domain = self.extract_domain(&reply_to_email);
                        let from_root = self.extract_root_domain(&from_domain);
                        let reply_to_root = self.extract_root_domain(&reply_to_domain);

                        // Check for legitimate business service patterns
                        let is_legitimate_service = from_domain.contains("netsuite.com")
                            || from_domain.contains("oracleemaildelivery.com")
                            || from_domain.contains("toast-restaurants.com")
                            || sender_domain.contains("oracleemaildelivery.com")
                            || (from_root.contains("lovepop") && reply_to_root.contains("lovepop"))
                            || (from_domain.contains("sparkpostmail.com")
                                && reply_to_root.contains("saily"));

                        // Only flag if different root domains (cross-domain mismatch) and not legitimate service
                        if from_root != reply_to_root
                            && from_root != "unknown"
                            && reply_to_root != "unknown"
                            && !is_legitimate_service
                        {
                            score += 40;
                            evidence.push(format!(
                                "Reply-To email ({}) differs from From email ({})",
                                reply_to_email, from_email
                            ));
                        }
                    }
                }
            }
        }

        // Check for sender name spoofing (random keywords)
        let spoofing_issues = self.analyze_sender_name_spoofing(&sender_info, context);
        score += spoofing_issues.len() as i32 * 40;
        evidence.extend(spoofing_issues);

        // Check for infrastructure-brand mismatch
        let infrastructure_issues = self.analyze_infrastructure_mismatch(&sender_info, context);
        score += infrastructure_issues.len() as i32 * 80;
        evidence.extend(infrastructure_issues);

        // Analyze brand impersonation
        let brand_issues = self.analyze_brand_impersonation(&sender_info, context);
        score += brand_issues.len() as i32 * 30;
        evidence.extend(brand_issues);

        // Analyze domain consistency
        let domain_issues = self.analyze_domain_consistency(&sender_info);
        score += domain_issues.len() as i32 * 20;
        evidence.extend(domain_issues);

        // Analyze display name spoofing
        let spoofing_issues = self.analyze_display_name_spoofing(&sender_info);
        score += spoofing_issues.len() as i32 * 15;
        evidence.extend(spoofing_issues);

        // Always check for enhanced brand impersonation (even if no other issues)
        let full_from_header = context.from_header.as_deref().unwrap_or("");
        let (brand_impersonation_score, brand_impersonation_evidence) =
            self.detect_suspicious_brand_impersonation(full_from_header, &sender_info.from_domain);
        score += brand_impersonation_score;
        evidence.extend(brand_impersonation_evidence);

        // Ensure we return a result if brand impersonation was detected, even if base score was 0
        let confidence = if evidence.is_empty() { 0.9 } else { 0.85 };

        // Apply professional credential discount (reduced when domain mismatch present)
        if self.detect_professional_credentials(context.from_header.as_deref().unwrap_or("")) {
            let reduction_factor = if sender_info.from_domain != sender_info.sender_domain {
                0.6 // 40% reduction when domain mismatch (was 70%)
            } else {
                0.3 // 70% reduction when domains match
            };
            score = (score as f32 * reduction_factor) as i32;
            evidence
                .push("Professional credentials detected - reduced scoring applied".to_string());
        }

        // Apply organization whitelist discount (reduced when domain mismatch present)
        if self.detect_legitimate_organization(&sender_info.from_domain) {
            let reduction_factor = if sender_info.from_domain != sender_info.sender_domain {
                0.8 // 20% reduction when domain mismatch (was 50%)
            } else {
                0.2 // 80% reduction when domains match
            };
            score = (score as f32 * reduction_factor) as i32;
            evidence.push(
                "Legitimate organization detected - significant scoring reduction applied"
                    .to_string(),
            );
        }

        // Apply legitimate business discount
        if self.is_legitimate_business(&sender_info) {
            score = (score as f32 * 0.3) as i32; // 70% reduction for legitimate businesses
            evidence.push("Legitimate business sender - reduced scoring applied".to_string());
        }

        // Apply corporate partnership discount
        if self.is_corporate_partnership(&sender_info.from_display_name, &sender_info.from_domain) {
            score = (score as f32 * 0.1) as i32; // 90% reduction for legitimate partnerships
            evidence.push(
                "Corporate partnership detected - significant scoring reduction applied"
                    .to_string(),
            );
        }

        // Apply platform recognition discount for known Q&A and development platforms
        let platform_domains = ["quora.com", "reddit.com", "stackoverflow.com", "github.com"];
        if platform_domains
            .iter()
            .any(|domain| sender_info.from_domain.contains(domain))
        {
            score = (score as f32 * 0.1) as i32; // 90% reduction for legitimate platforms
            evidence.push(
                "Legitimate platform detected - significant scoring reduction applied".to_string(),
            );
        }

        // Check for domain-content mismatch
        let domain_content_score =
            self.check_domain_content_mismatch(context, &sender_info.from_domain);
        score += domain_content_score.0;
        evidence.extend(domain_content_score.1);

        // Check for excessive sender length
        let sender_length_score = self.check_sender_length(context);
        score += sender_length_score.0;
        evidence.extend(sender_length_score.1);

        FeatureScore {
            feature_name: "Sender Alignment".to_string(),
            score,
            confidence,
            evidence,
        }
    }

    fn name(&self) -> &str {
        "sender_alignment"
    }
}

impl SenderAlignmentAnalyzer {
    fn is_job_related_content(&self, subject: &str, body: &str) -> bool {
        let job_indicators = [
            "job",
            "jobs",
            "role",
            "roles",
            "position",
            "positions",
            "career",
            "careers",
            "hiring",
            "employment",
            "opportunity",
            "opportunities",
            "recommendation",
            "recommendations",
            "available",
            "opening",
            "openings",
            "apply",
            "application",
        ];

        let combined_text = format!("{} {}", subject.to_lowercase(), body.to_lowercase());

        job_indicators
            .iter()
            .any(|&indicator| combined_text.contains(indicator))
    }

    fn check_domain_content_mismatch(
        &self,
        context: &MailContext,
        domain: &str,
    ) -> (i32, Vec<String>) {
        let mut score = 0;
        let mut evidence = Vec::new();

        // Get email content
        let subject = context.subject.as_deref().unwrap_or("");
        let body = context.body.as_deref().unwrap_or("");
        let combined_content = format!("{} {}", subject, body).to_lowercase();

        // Define domain categories and their expected content
        let medical_domains = ["gastricbypass", "weightloss", "diet", "supplement"];
        let financial_domains = ["bank", "credit", "finance", "loan", "investment", "trading"];

        // Check for medical domain with non-medical content (only for suspicious medical domains)
        if medical_domains.iter().any(|&med| domain.contains(med)) {
            // Only flag if it's clearly financial scam content, not legitimate medical billing
            if (combined_content.contains("creditcard") || combined_content.contains("credit card"))
                && (combined_content.contains("bill") || combined_content.contains("resolution"))
                && !combined_content.contains("medical")
                && !combined_content.contains("health")
            {
                score += 40;
                evidence.push("Medical domain sending credit card billing content".to_string());
            }
        }

        // Check for financial domain with non-financial content
        if financial_domains.iter().any(|&fin| domain.contains(fin))
            && (combined_content.contains("medical")
                || combined_content.contains("health")
                || combined_content.contains("doctor")
                || combined_content.contains("treatment"))
        {
            score += 35;
            evidence.push("Financial domain sending medical content".to_string());
        }

        (score, evidence)
    }

    fn check_sender_length(&self, context: &MailContext) -> (i32, Vec<String>) {
        let mut score = 0;
        let mut evidence = Vec::new();

        if let Some(from_header) = &context.from_header {
            // Extract email address from From header
            if let Some(email_start) = from_header.rfind('<') {
                if let Some(email_end) = from_header.rfind('>') {
                    let email = &from_header[email_start + 1..email_end];
                    let email_length = email.len();

                    if email_length > 60 {
                        score += 25;
                        evidence.push(format!(
                            "Excessively long sender email address ({} characters)",
                            email_length
                        ));
                    } else if email_length > 45 {
                        score += 15;
                        evidence.push(format!(
                            "Very long sender email address ({} characters)",
                            email_length
                        ));
                    }
                }
            }
        }

        (score, evidence)
    }
}
impl SenderAlignmentAnalyzer {}
