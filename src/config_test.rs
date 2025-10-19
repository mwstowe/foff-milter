use crate::legacy_config::{Config, Criteria, FilterRule};
use regex::Regex;
use std::time::Instant;

/// Sample email data for testing regex patterns
pub struct EmailTestData {
    pub sender: String,
    pub recipient: String,
    pub subject: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl EmailTestData {
    pub fn new(sender: &str, recipient: &str, subject: &str) -> Self {
        Self {
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            subject: subject.to_string(),
            headers: Vec::new(),
            body: String::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn with_body(mut self, body: &str) -> Self {
        self.body = body.to_string();
        self
    }
}

/// Comprehensive configuration testing results
#[derive(Debug)]
pub struct ConfigTestResults {
    pub valid: bool,
    pub total_rules: usize,
    pub total_patterns: usize,
    pub pattern_errors: Vec<String>,
    pub performance_warnings: Vec<String>,
    pub test_failures: Vec<String>,
    pub total_test_time_ms: u128,
}

impl Default for ConfigTestResults {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigTestResults {
    pub fn new() -> Self {
        Self {
            valid: true,
            total_rules: 0,
            total_patterns: 0,
            pattern_errors: Vec::new(),
            performance_warnings: Vec::new(),
            test_failures: Vec::new(),
            total_test_time_ms: 0,
        }
    }

    pub fn add_error(&mut self, error: String) {
        self.valid = false;
        self.pattern_errors.push(error);
    }

    pub fn add_warning(&mut self, warning: String) {
        self.performance_warnings.push(warning);
    }

    pub fn add_test_failure(&mut self, failure: String) {
        self.valid = false;
        self.test_failures.push(failure);
    }
}

/// Generate comprehensive test email corpus
pub fn generate_test_email_corpus() -> Vec<EmailTestData> {
    vec![
        // Legitimate emails
        EmailTestData::new("user@example.com", "recipient@company.com", "Meeting tomorrow")
            .with_header("X-Mailer", "Outlook 16.0")
            .with_header("Return-Path", "user@example.com")
            .with_body("Hi, let's meet tomorrow at 2pm."),

        EmailTestData::new("noreply@paypal.com", "user@company.com", "Your PayPal receipt")
            .with_header("DKIM-Signature", "d=paypal.com")
            .with_header("Return-Path", "noreply@paypal.com")
            .with_body("Thank you for your payment."),

        EmailTestData::new("support@amazon.com", "customer@example.com", "Order confirmation")
            .with_header("X-Mailer", "Amazon SES")
            .with_header("DKIM-Signature", "d=amazon.com")
            .with_body("Your order has been confirmed."),

        // Suspicious emails - Free email services
        EmailTestData::new("randomuser123@gmail.com", "target@company.com", "Urgent: Account suspended")
            .with_header("X-Mailer", "Gmail")
            .with_header("Return-Path", "randomuser123@gmail.com")
            .with_body("Your account will be suspended unless you click here."),

        EmailTestData::new("admin@outlook.com", "victim@company.com", "Password reset required")
            .with_header("X-Mailer", "Outlook.com")
            .with_header("Return-Path", "admin@outlook.com")
            .with_body("Click here to reset your password immediately."),

        // Suspicious TLDs
        EmailTestData::new("service@suspicious.tk", "user@company.com", "You won the lottery!")
            .with_header("X-Mailer", "Unknown")
            .with_header("Return-Path", "service@suspicious.tk")
            .with_body("Congratulations! You've won $1,000,000!"),

        EmailTestData::new("admin@phishing.ml", "target@company.com", "Account verification needed")
            .with_header("X-Mailer", "Custom Mailer")
            .with_header("Return-Path", "admin@phishing.ml")
            .with_body("Verify your account or it will be deleted."),

        EmailTestData::new("noreply@scam.ga", "victim@company.com", "Immediate action required")
            .with_header("X-Mailer", "Bulk Mailer")
            .with_header("Return-Path", "noreply@scam.ga")
            .with_body("Your account has been compromised."),

        // SendGrid examples
        EmailTestData::new("sender@example.com", "recipient@company.com", "Newsletter")
            .with_header("Return-Path", "bounce@sendgrid.net")
            .with_header("DKIM-Signature", "d=sendgrid.net")
            .with_body("This is a legitimate newsletter."),

        EmailTestData::new("phisher@fake.com", "target@company.com", "Fake PayPal alert")
            .with_header("Return-Path", "bounce@sendgrid.net")
            .with_header("DKIM-Signature", "d=suspicious.tk")
            .with_body("Your PayPal account has been limited."),

        // Language detection tests
        EmailTestData::new("sender@example.com", "recipient@company.com", "こんにちは")
            .with_header("X-Mailer", "Test Mailer")
            .with_body("これは日本語のテストメールです。"),

        EmailTestData::new("sender@example.com", "recipient@company.com", "你好")
            .with_header("X-Mailer", "Test Mailer")
            .with_body("这是中文测试邮件。"),

        // Unsubscribe link tests
        EmailTestData::new("newsletter@company.com", "subscriber@example.com", "Weekly Newsletter")
            .with_header("List-Unsubscribe", "<http://example.com/unsubscribe>")
            .with_body("Newsletter content with unsubscribe link: http://example.com/unsubscribe"),

        EmailTestData::new("spam@suspicious.tk", "victim@company.com", "Special offer")
            .with_header("List-Unsubscribe", "<http://192.168.1.1/unsubscribe>")
            .with_body("Special offer! Unsubscribe: http://192.168.1.1/unsubscribe"),

        // Attachment tests
        EmailTestData::new("sender@example.com", "recipient@company.com", "Document attached")
            .with_header("Content-Type", "multipart/mixed")
            .with_body("Content-Type: application/pdf\nContent-Disposition: attachment; filename=\"document.pdf\"\n\n[PDF content here]"),

        // Edge cases
        EmailTestData::new("", "recipient@company.com", "Empty sender")
            .with_body("Test email with empty sender."),

        EmailTestData::new("user@example.com", "", "Empty recipient")
            .with_body("Test email with empty recipient."),

        EmailTestData::new("user@example.com", "recipient@company.com", "")
            .with_body("Test email with empty subject."),

        // Empty content test cases
        EmailTestData::new("test@gmail.com", "victim@company.com", "")
            .with_body(""),  // Completely empty

        EmailTestData::new("reconnaissance@suspicious.tk", "target@company.com", "test")
            .with_body("   "),  // Just whitespace

        EmailTestData::new("empty@example.com", "user@company.com", "hi")
            .with_body("."),  // Just punctuation

        EmailTestData::new("minimal@gmail.com", "target@company.com", "")
            .with_body("hello"),  // Minimal content

        EmailTestData::new("placeholder@test.com", "user@company.com", "testing")
            .with_body("test"),  // Test content

        EmailTestData::new("automated@paypal.com", "customer@company.com", "")
            .with_body("--\nSent from PayPal\nUnsubscribe: http://paypal.com/unsubscribe"),  // Just signature

        EmailTestData::new("tracking@suspicious.tk", "victim@company.com", "")
            .with_body("<html><body></body></html>"),  // Empty HTML

        EmailTestData::new("recon@attacker.com", "target@company.com", "")
            .with_body("Thanks\n--\nBest regards"),  // Just signature content

        // Unicode and special characters
        EmailTestData::new("üser@exämple.com", "recipient@company.com", "Unicode test: café résumé naïve")
            .with_body("Testing unicode characters: ñoño, café, résumé, naïve, 北京, москва"),

        // Very long patterns
        EmailTestData::new(&"a".repeat(100), "recipient@company.com", &"b".repeat(200))
            .with_body(&"c".repeat(1000)),
    ]
}

/// Validate all regex patterns in a configuration
pub fn validate_config_comprehensive(config: &Config) -> ConfigTestResults {
    let start_time = Instant::now();
    let mut results = ConfigTestResults::new();

    results.total_rules = config.rules.len();

    // Generate test corpus
    let test_emails = generate_test_email_corpus();

    for (rule_idx, rule) in config.rules.iter().enumerate() {
        validate_rule_comprehensive(rule, rule_idx, &test_emails, &mut results);
    }

    results.total_test_time_ms = start_time.elapsed().as_millis();
    results
}

/// Validate a single rule comprehensively
fn validate_rule_comprehensive(
    rule: &FilterRule,
    rule_idx: usize,
    test_emails: &[EmailTestData],
    results: &mut ConfigTestResults,
) {
    validate_criteria_comprehensive(&rule.criteria, rule_idx, &rule.name, test_emails, results);
}

/// Validate criteria and all nested criteria
fn validate_criteria_comprehensive(
    criteria: &Criteria,
    rule_idx: usize,
    rule_name: &str,
    test_emails: &[EmailTestData],
    results: &mut ConfigTestResults,
) {
    match criteria {
        Criteria::MailerPattern { pattern } => {
            validate_pattern("MailerPattern", pattern, rule_idx, rule_name, results);
            test_pattern_against_emails(
                "X-Mailer",
                pattern,
                test_emails,
                rule_idx,
                rule_name,
                results,
            );
        }
        Criteria::SenderPattern { pattern } => {
            validate_pattern("SenderPattern", pattern, rule_idx, rule_name, results);
            test_sender_pattern(pattern, test_emails, rule_idx, rule_name, results);
        }
        Criteria::RecipientPattern { pattern } => {
            validate_pattern("RecipientPattern", pattern, rule_idx, rule_name, results);
            test_recipient_pattern(pattern, test_emails, rule_idx, rule_name, results);
        }
        Criteria::SubjectPattern { pattern } => {
            validate_pattern("SubjectPattern", pattern, rule_idx, rule_name, results);
            test_subject_pattern(pattern, test_emails, rule_idx, rule_name, results);
        }
        Criteria::HeaderPattern { header, pattern } => {
            validate_pattern(
                &format!("HeaderPattern({header})"),
                pattern,
                rule_idx,
                rule_name,
                results,
            );
            test_pattern_against_emails(header, pattern, test_emails, rule_idx, rule_name, results);
        }
        Criteria::UnsubscribeLinkPattern { pattern } => {
            validate_pattern(
                "UnsubscribeLinkPattern",
                pattern,
                rule_idx,
                rule_name,
                results,
            );
            test_unsubscribe_pattern(pattern, test_emails, rule_idx, rule_name, results);
        }
        Criteria::And { criteria } => {
            for sub_criteria in criteria {
                validate_criteria_comprehensive(
                    sub_criteria,
                    rule_idx,
                    rule_name,
                    test_emails,
                    results,
                );
            }
        }
        Criteria::Or { criteria } => {
            for sub_criteria in criteria {
                validate_criteria_comprehensive(
                    sub_criteria,
                    rule_idx,
                    rule_name,
                    test_emails,
                    results,
                );
            }
        }
        // Non-regex criteria don't need pattern validation
        _ => {}
    }
}

/// Validate a single regex pattern
fn validate_pattern(
    pattern_type: &str,
    pattern: &str,
    rule_idx: usize,
    rule_name: &str,
    results: &mut ConfigTestResults,
) {
    results.total_patterns += 1;

    // Test regex compilation
    let regex_result = Regex::new(pattern);
    match regex_result {
        Ok(regex) => {
            // Test performance with a simple string
            let start = Instant::now();
            let test_string = "test@example.com";
            for _ in 0..1000 {
                let _ = regex.is_match(test_string);
            }
            let duration = start.elapsed();

            // Warn about slow patterns (>1ms for 1000 iterations)
            if duration.as_millis() > 1 {
                results.add_warning(format!(
                    "Rule {} ({}): {} pattern '{}' is slow ({:.2}ms for 1000 iterations)",
                    rule_idx + 1,
                    rule_name,
                    pattern_type,
                    pattern,
                    duration.as_secs_f64() * 1000.0
                ));
            }

            // Check for potentially problematic patterns
            if pattern.contains(".*.*") {
                results.add_warning(format!(
                    "Rule {} ({}): {} pattern '{}' contains nested .* which may cause performance issues",
                    rule_idx + 1, rule_name, pattern_type, pattern
                ));
            }

            if pattern.len() > 200 {
                results.add_warning(format!(
                    "Rule {} ({}): {} pattern is very long ({} chars) - consider simplifying",
                    rule_idx + 1,
                    rule_name,
                    pattern_type,
                    pattern.len()
                ));
            }
        }
        Err(e) => {
            results.add_error(format!(
                "Rule {} ({}): Invalid {} pattern '{}': {}",
                rule_idx + 1,
                rule_name,
                pattern_type,
                pattern,
                e
            ));
        }
    }
}

/// Test sender pattern against email corpus
fn test_sender_pattern(
    pattern: &str,
    test_emails: &[EmailTestData],
    rule_idx: usize,
    rule_name: &str,
    results: &mut ConfigTestResults,
) {
    if let Ok(regex) = Regex::new(pattern) {
        for (email_idx, email) in test_emails.iter().enumerate() {
            match std::panic::catch_unwind(|| regex.is_match(&email.sender)) {
                Ok(_) => {} // Success
                Err(_) => {
                    results.add_test_failure(format!(
                        "Rule {} ({}): SenderPattern '{}' panicked on test email {} (sender: '{}')",
                        rule_idx + 1,
                        rule_name,
                        pattern,
                        email_idx + 1,
                        email.sender
                    ));
                }
            }
        }
    }
}

/// Test recipient pattern against email corpus
fn test_recipient_pattern(
    pattern: &str,
    test_emails: &[EmailTestData],
    rule_idx: usize,
    rule_name: &str,
    results: &mut ConfigTestResults,
) {
    if let Ok(regex) = Regex::new(pattern) {
        for (email_idx, email) in test_emails.iter().enumerate() {
            match std::panic::catch_unwind(|| regex.is_match(&email.recipient)) {
                Ok(_) => {} // Success
                Err(_) => {
                    results.add_test_failure(format!(
                        "Rule {} ({}): RecipientPattern '{}' panicked on test email {} (recipient: '{}')",
                        rule_idx + 1, rule_name, pattern, email_idx + 1, email.recipient
                    ));
                }
            }
        }
    }
}

/// Test subject pattern against email corpus
fn test_subject_pattern(
    pattern: &str,
    test_emails: &[EmailTestData],
    rule_idx: usize,
    rule_name: &str,
    results: &mut ConfigTestResults,
) {
    if let Ok(regex) = Regex::new(pattern) {
        for (email_idx, email) in test_emails.iter().enumerate() {
            match std::panic::catch_unwind(|| regex.is_match(&email.subject)) {
                Ok(_) => {} // Success
                Err(_) => {
                    results.add_test_failure(format!(
                        "Rule {} ({}): SubjectPattern '{}' panicked on test email {} (subject: '{}')",
                        rule_idx + 1, rule_name, pattern, email_idx + 1, email.subject
                    ));
                }
            }
        }
    }
}

/// Test header pattern against email corpus
fn test_pattern_against_emails(
    header_name: &str,
    pattern: &str,
    test_emails: &[EmailTestData],
    rule_idx: usize,
    rule_name: &str,
    results: &mut ConfigTestResults,
) {
    if let Ok(regex) = Regex::new(pattern) {
        for (email_idx, email) in test_emails.iter().enumerate() {
            // Find the header value
            let header_value = email
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(header_name))
                .map(|(_, value)| value.as_str())
                .unwrap_or("");

            match std::panic::catch_unwind(|| regex.is_match(header_value)) {
                Ok(_) => {} // Success
                Err(_) => {
                    results.add_test_failure(format!(
                        "Rule {} ({}): HeaderPattern({}) '{}' panicked on test email {} (header value: '{}')",
                        rule_idx + 1, rule_name, header_name, pattern, email_idx + 1, header_value
                    ));
                }
            }
        }
    }
}

/// Test unsubscribe pattern against email corpus
fn test_unsubscribe_pattern(
    pattern: &str,
    test_emails: &[EmailTestData],
    rule_idx: usize,
    rule_name: &str,
    results: &mut ConfigTestResults,
) {
    if let Ok(regex) = Regex::new(pattern) {
        for (email_idx, email) in test_emails.iter().enumerate() {
            // Test against body content (where unsubscribe links typically appear)
            match std::panic::catch_unwind(|| regex.is_match(&email.body)) {
                Ok(_) => {} // Success
                Err(_) => {
                    results.add_test_failure(format!(
                        "Rule {} ({}): UnsubscribeLinkPattern '{}' panicked on test email {} (body length: {})",
                        rule_idx + 1, rule_name, pattern, email_idx + 1, email.body.len()
                    ));
                }
            }
        }
    }
}

/// Print comprehensive test results
pub fn print_test_results(results: &ConfigTestResults) {
    if results.valid {
        println!("✅ Configuration validation PASSED!");
    } else {
        println!("❌ Configuration validation FAILED!");
    }

    println!();
    println!("📊 Test Summary:");
    println!("  Total rules: {}", results.total_rules);
    println!("  Total regex patterns: {}", results.total_patterns);
    println!("  Test time: {}ms", results.total_test_time_ms);

    if !results.pattern_errors.is_empty() {
        println!();
        println!("🚨 Pattern Errors ({}):", results.pattern_errors.len());
        for error in &results.pattern_errors {
            println!("  • {error}");
        }
    }

    if !results.test_failures.is_empty() {
        println!();
        println!("💥 Test Failures ({}):", results.test_failures.len());
        for failure in &results.test_failures {
            println!("  • {failure}");
        }
    }

    if !results.performance_warnings.is_empty() {
        println!();
        println!(
            "⚠️  Performance Warnings ({}):",
            results.performance_warnings.len()
        );
        for warning in &results.performance_warnings {
            println!("  • {warning}");
        }
    }

    if results.valid && results.performance_warnings.is_empty() {
        println!();
        println!("🎉 All patterns are valid and performant!");
    }
}
