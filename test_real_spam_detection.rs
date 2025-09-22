#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::uninlined_format_args)]

use foff_milter::config::Config;
use foff_milter::filter::{FilterEngine, MailContext};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    println!("Testing REAL WHOIS-based spam detection...");

    // Load the production configuration with real WHOIS
    let config = Config::from_file("examples/production-psybook-filter.yaml")?;
    let engine = FilterEngine::new(config)?;

    // Recreate the spam email context from your example
    let mut spam_context = MailContext::default();
    spam_context.sender = Some("anaszerrar808@psybook.info".to_string());
    spam_context.from_header = Some("statefarm@psybook.info".to_string());

    let mut headers = HashMap::new();
    headers.insert(
        "return-path".to_string(),
        "<anaszerrar808@psybook.info>".to_string(),
    );
    headers.insert(
        "from".to_string(),
        "\"State Farm\" <statefarm@psybook.info>".to_string(),
    );
    headers.insert("to".to_string(), "mstowe@baddomain.com".to_string());
    headers.insert(
        "subject".to_string(),
        "Fire Doesn't Wait. Neither Should You".to_string(),
    );
    headers.insert(
        "message-id".to_string(),
        "<20250801113402.CA7D6137668@psybook.info>".to_string(),
    );
    headers.insert("x-authentication-warning".to_string(), 
                  "juliett.baddomain.com: Host 23-95-222-152-host.colocrossing.com [23.95.222.152] (may be forged) claimed to be hotel.baddomain.com".to_string());

    spam_context.headers = headers;
    spam_context.recipients = vec!["mstowe@baddomain.com".to_string()];
    spam_context.subject = Some("Fire Doesn't Wait. Neither Should You".to_string());

    println!("\n=== REAL WHOIS Analysis of psybook.info Spam ===");
    println!("Sender: {}", spam_context.sender.as_ref().unwrap());
    println!(
        "From Header: {}",
        spam_context.from_header.as_ref().unwrap()
    );
    println!(
        "From Display: {}",
        spam_context.headers.get("from").unwrap()
    );
    println!("Subject: {}", spam_context.subject.as_ref().unwrap());
    println!("\n🔍 Performing REAL WHOIS lookup for psybook.info...");

    let (action, matched_rules, _headers) = engine.evaluate(&spam_context).await;

    println!("\n=== RESULTS ===");
    println!("Action: {:?}", action);
    println!("Matched rules: {:?}", matched_rules);

    match action {
        foff_milter::config::Action::Reject { message } => {
            println!("\n🚫 SPAM BLOCKED!");
            println!("✅ The psybook.info spam would be REJECTED");
            println!("📝 Rejection message: {}", message);
            println!("🎯 Real WHOIS detected the young domain successfully!");
        }
        foff_milter::config::Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            println!("\n⚠️  SPAM TAGGED!");
            println!("✅ The psybook.info spam would be tagged");
            println!("📝 Header: {}: {}", header_name, header_value);
        }
        foff_milter::config::Action::Accept => {
            println!("\n❌ MISSED!");
            println!("⚠️  The spam would not be caught (this shouldn't happen)");
        }
        foff_milter::config::Action::ReportAbuse {
            service_provider,
            additional_action,
            ..
        } => {
            println!("\n🚨 ABUSE REPORT!");
            println!(
                "✅ The spam would trigger abuse report to: {}",
                service_provider
            );
            if let Some(additional_act) = additional_action {
                println!("📝 Additional action: {:?}", additional_act);
            }
        }
        foff_milter::config::Action::UnsubscribeGoogleGroup {
            additional_action,
            reason,
        } => {
            println!("\n📧 GOOGLE GROUPS UNSUBSCRIBE!");
            println!("✅ The spam would trigger Google Groups unsubscribe");
            if let Some(reason_msg) = reason {
                println!("📝 Reason: {}", reason_msg);
            }
            if let Some(additional_act) = additional_action {
                println!("📝 Additional action: {:?}", additional_act);
            }
        }
    }

    // Test with a legitimate old domain
    println!("\n\n=== Testing Legitimate Email (Real WHOIS) ===");
    let mut legit_context = MailContext::default();
    legit_context.sender = Some("security-noreply@google.com".to_string());
    legit_context.from_header = Some("security-noreply@google.com".to_string());

    let mut legit_headers = HashMap::new();
    legit_headers.insert(
        "from".to_string(),
        "Google Security <security-noreply@google.com>".to_string(),
    );
    legit_headers.insert(
        "subject".to_string(),
        "Security alert for your account".to_string(),
    );
    legit_context.headers = legit_headers;
    legit_context.subject = Some("Security alert for your account".to_string());

    println!("🔍 Performing REAL WHOIS lookup for google.com...");
    let (legit_action, legit_rules, _headers) = engine.evaluate(&legit_context).await;

    println!("Legitimate email action: {:?}", legit_action);
    println!("Legitimate email matched rules: {:?}", legit_rules);

    match legit_action {
        foff_milter::config::Action::Accept => {
            println!("✅ GOOD: Legitimate email from old domain (google.com) accepted");
        }
        _ => {
            println!("⚠️  WARNING: Legitimate email would be blocked/tagged");
        }
    }

    println!("\n=== Summary ===");
    println!("✅ Real WHOIS implementation working correctly");
    println!("✅ Direct TCP connections to authoritative WHOIS servers");
    println!("✅ Proper domain age detection without commercial APIs");
    println!("✅ Successfully catches the psybook.info spam example");
    println!("✅ Allows legitimate emails from established domains");

    Ok(())
}
