#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::uninlined_format_args)]

use foff_milter::config::Config;
use foff_milter::filter::{FilterEngine, MailContext};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    println!("Testing the specific spam example from your headers...");

    // Create a configuration that would catch the psybook.info spam
    let config_yaml = r#"
socket_path: "/var/run/foff-milter.sock"
default_action:
  type: "Accept"

rules:
  - name: "Block young domains impersonating State Farm"
    criteria:
      type: "And"
      criteria:
        - type: "DomainAge"
          max_age_days: 120
          check_sender: true
          use_mock_data: true
        - type: "HeaderPattern"
          header: "from"
          pattern: "(?i)state\\s*farm"
    action:
      type: "Reject"
      message: "Young domain impersonating State Farm blocked"
  
  - name: "Tag any young domain"
    criteria:
      type: "DomainAge"
      max_age_days: 365
      check_sender: true
      use_mock_data: true
    action:
      type: "TagAsSpam"
      header_name: "X-Spam-Young-Domain"
      header_value: "Domain less than 1 year old"
"#;

    let config: Config = serde_yaml::from_str(config_yaml)?;
    let engine = FilterEngine::new(config)?;

    // Recreate the spam email context from your example
    let mut context = MailContext::default();
    context.sender = Some("anaszerrar808@psybook.info".to_string());
    context.from_header = Some("statefarm@psybook.info".to_string());

    let mut headers = HashMap::new();
    headers.insert(
        "return-path".to_string(),
        "<anaszerrar808@psybook.info>".to_string(),
    );
    headers.insert(
        "from".to_string(),
        "\"State Farm\" <statefarm@psybook.info>".to_string(),
    );
    headers.insert("to".to_string(), "mjohnson@example.com".to_string());
    headers.insert(
        "subject".to_string(),
        "Fire Doesn't Wait. Neither Should You".to_string(),
    );
    headers.insert(
        "message-id".to_string(),
        "<20250801113402.CA7D6137668@psybook.info>".to_string(),
    );
    headers.insert("x-authentication-warning".to_string(), 
                  "juliett.example.com: Host 23-95-222-152-host.colocrossing.com [23.95.222.152] (may be forged) claimed to be hotel.example.com".to_string());

    context.headers = headers;
    context.recipients = vec!["mjohnson@example.com".to_string()];
    context.subject = Some("Fire Doesn't Wait. Neither Should You".to_string());

    println!("\n=== Analyzing the psybook.info spam example ===");
    println!("Sender: {}", context.sender.as_ref().unwrap());
    println!("From Header: {}", context.from_header.as_ref().unwrap());
    println!("From Display: {}", context.headers.get("from").unwrap());
    println!("Subject: {}", context.subject.as_ref().unwrap());

    let (action, matched_rules) = engine.evaluate(&context).await;

    println!("\n=== Results ===");
    println!("Action: {:?}", action);
    println!("Matched rules: {:?}", matched_rules);

    match action {
        foff_milter::config::Action::Reject { message } => {
            println!("\n✅ SUCCESS: This spam would be REJECTED");
            println!("Rejection message: {}", message);
        }
        foff_milter::config::Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            println!("\n⚠️  TAGGED: This spam would be tagged as spam");
            println!("Header: {}: {}", header_name, header_value);
        }
        foff_milter::config::Action::Accept => {
            println!("\n❌ MISSED: This spam would be accepted (not caught)");
        }
    }

    // Test with a legitimate email from an old domain
    println!("\n\n=== Testing legitimate email from old domain ===");
    let mut legit_context = MailContext::default();
    legit_context.sender = Some("noreply@google.com".to_string());
    legit_context.from_header = Some("noreply@google.com".to_string());

    let mut legit_headers = HashMap::new();
    legit_headers.insert(
        "from".to_string(),
        "Google Security <noreply@google.com>".to_string(),
    );
    legit_headers.insert(
        "subject".to_string(),
        "Security alert for your account".to_string(),
    );
    legit_context.headers = legit_headers;
    legit_context.subject = Some("Security alert for your account".to_string());

    let (legit_action, legit_rules) = engine.evaluate(&legit_context).await;

    println!("Legitimate email action: {:?}", legit_action);
    println!("Legitimate email matched rules: {:?}", legit_rules);

    match legit_action {
        foff_milter::config::Action::Accept => {
            println!("✅ GOOD: Legitimate email would be accepted");
        }
        _ => {
            println!("⚠️  WARNING: Legitimate email would be blocked/tagged");
        }
    }

    Ok(())
}
