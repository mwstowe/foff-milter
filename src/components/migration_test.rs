//! Migration Validation Tests
//!
//! Tests to ensure new components maintain compatibility with existing functionality

use crate::components::filter_engine_v2::FilterEngineV2;
use crate::MailContext;
use std::collections::HashMap;

/// Test that new components can handle basic email processing
#[tokio::test]
async fn test_basic_email_processing() {
    let engine = FilterEngineV2::new();
    let context = create_legitimate_email_context();

    let (action, _rules, headers) = engine.evaluate_v2(&context).await;

    // Should accept legitimate email
    assert!(matches!(action, crate::heuristic_config::Action::Accept));

    // Should have analysis headers
    assert!(headers.iter().any(|(name, _)| name == "X-FOFF-Score-V2"));
}

/// Test that new components can detect obvious spam
#[tokio::test]
async fn test_spam_detection() {
    let engine = FilterEngineV2::new();
    let context = create_spam_email_context();

    let (action, _rules, _headers) = engine.evaluate_v2(&context).await;

    // Should tag or reject spam
    assert!(matches!(
        action,
        crate::heuristic_config::Action::TagAsSpam { .. }
            | crate::heuristic_config::Action::Reject { .. }
    ));
}

/// Test authentication analysis
#[tokio::test]
async fn test_authentication_analysis() {
    let engine = FilterEngineV2::new();
    let context = create_authenticated_email_context();

    let (action, rules, _headers) = engine.evaluate_v2(&context).await;

    // Should have authentication analysis
    assert!(rules
        .iter()
        .any(|rule| rule.contains("AuthenticationAnalyzer")));
}

/// Test mismatch detection
#[tokio::test]
async fn test_mismatch_detection() {
    let engine = FilterEngineV2::new();
    let context = create_mismatch_email_context();

    let (action, rules, _headers) = engine.evaluate_v2(&context).await;

    // Should detect mismatches
    assert!(rules.iter().any(|rule| rule.contains("MismatchAnalyzer")));
}

// Helper functions to create test contexts

fn create_legitimate_email_context() -> MailContext {
    let mut headers = HashMap::new();
    headers.insert("From".to_string(), "newsletter@amazon.com".to_string());
    headers.insert("Subject".to_string(), "Your Order Update".to_string());
    headers.insert(
        "Authentication-Results".to_string(),
        "dkim=pass spf=pass".to_string(),
    );
    headers.insert(
        "List-Unsubscribe".to_string(),
        "<mailto:unsubscribe@amazon.com>".to_string(),
    );

    MailContext {
        sender: Some("newsletter@amazon.com".to_string()),
        from_header: Some("newsletter@amazon.com".to_string()),
        recipients: vec!["customer@example.com".to_string()],
        headers,
        mailer: None,
        subject: Some("Your Order Update".to_string()),
        hostname: None,
        helo: None,
        body: Some("Your recent order has been shipped.".to_string()),
        last_header_name: None,
        attachments: Vec::new(),
        extracted_media_text: String::new(),
        is_legitimate_business: true,
        is_first_hop: true,
        forwarding_source: None,
        proximate_mailer: None,
        normalized: None,
        dkim_verification: None,
    }
}

fn create_spam_email_context() -> MailContext {
    let mut headers = HashMap::new();
    headers.insert(
        "From".to_string(),
        "PayPal Security <noreply@suspicious-domain.com>".to_string(),
    );
    headers.insert(
        "Subject".to_string(),
        "URGENT: Verify Your Account Now!".to_string(),
    );

    MailContext {
        sender: Some("noreply@suspicious-domain.com".to_string()),
        from_header: Some("PayPal Security <noreply@suspicious-domain.com>".to_string()),
        recipients: vec!["victim@example.com".to_string()],
        headers,
        mailer: None,
        subject: Some("URGENT: Verify Your Account Now!".to_string()),
        hostname: None,
        helo: None,
        body: Some(
            "Click here to verify your PayPal account immediately or it will be suspended!"
                .to_string(),
        ),
        last_header_name: None,
        attachments: Vec::new(),
        extracted_media_text: String::new(),
        is_legitimate_business: false,
        is_first_hop: true,
        forwarding_source: None,
        proximate_mailer: None,
        normalized: None,
        dkim_verification: None,
    }
}

fn create_authenticated_email_context() -> MailContext {
    let mut headers = HashMap::new();
    headers.insert("From".to_string(), "support@paypal.com".to_string());
    headers.insert("Subject".to_string(), "Payment Receipt".to_string());
    headers.insert(
        "Authentication-Results".to_string(),
        "dkim=pass spf=pass dmarc=pass".to_string(),
    );
    headers.insert(
        "DKIM-Signature".to_string(),
        "v=1; a=rsa-sha256; d=paypal.com; s=selector1".to_string(),
    );

    MailContext {
        sender: Some("support@paypal.com".to_string()),
        from_header: Some("support@paypal.com".to_string()),
        recipients: vec!["customer@example.com".to_string()],
        headers,
        mailer: None,
        subject: Some("Payment Receipt".to_string()),
        hostname: None,
        helo: None,
        body: Some("Thank you for your payment.".to_string()),
        last_header_name: None,
        attachments: Vec::new(),
        extracted_media_text: String::new(),
        is_legitimate_business: true,
        is_first_hop: true,
        forwarding_source: None,
        proximate_mailer: None,
        normalized: None,
        dkim_verification: None,
    }
}

fn create_mismatch_email_context() -> MailContext {
    let mut headers = HashMap::new();
    headers.insert(
        "From".to_string(),
        "Amazon Security <noreply@fake-amazon.com>".to_string(),
    );
    headers.insert(
        "Subject".to_string(),
        "Amazon Account Verification Required".to_string(),
    );

    MailContext {
        sender: Some("noreply@fake-amazon.com".to_string()),
        from_header: Some("Amazon Security <noreply@fake-amazon.com>".to_string()),
        recipients: vec!["target@example.com".to_string()],
        headers,
        mailer: None,
        subject: Some("Amazon Account Verification Required".to_string()),
        hostname: None,
        helo: None,
        body: Some("Your Amazon account needs verification. Click here to verify.".to_string()),
        last_header_name: None,
        attachments: Vec::new(),
        extracted_media_text: String::new(),
        is_legitimate_business: false,
        is_first_hop: true,
        forwarding_source: None,
        proximate_mailer: None,
        normalized: None,
        dkim_verification: None,
    }
}
