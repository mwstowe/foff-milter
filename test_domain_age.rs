#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::uninlined_format_args)]

use foff_milter::config::Config;
use foff_milter::filter::{FilterEngine, MailContext};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    println!("Testing domain age functionality...");

    // Load the example configuration
    let config = Config::from_file("examples/domain-age-example.yaml")?;
    let engine = FilterEngine::new(config)?;

    // Test case 1: Email from psybook.info (young domain in mock data)
    let mut context1 = MailContext::default();
    context1.sender = Some("anaszerrar808@psybook.info".to_string());
    context1.from_header = Some("anaszerrar808@psybook.info".to_string());

    let mut headers1 = HashMap::new();
    headers1.insert(
        "from".to_string(),
        "\"State Farm\" <statefarm@psybook.info>".to_string(),
    );
    context1.headers = headers1;

    println!("\n=== Test Case 1: psybook.info (young domain) ===");
    let (action1, rules1, _headers) = engine.evaluate(&context1).await;
    println!("Action: {:?}", action1);
    println!("Matched rules: {:?}", rules1);

    // Test case 2: Email from google.com (old domain in mock data)
    let mut context2 = MailContext::default();
    context2.sender = Some("test@google.com".to_string());
    context2.from_header = Some("test@google.com".to_string());

    let mut headers2 = HashMap::new();
    headers2.insert(
        "from".to_string(),
        "Test User <test@google.com>".to_string(),
    );
    context2.headers = headers2;

    println!("\n=== Test Case 2: google.com (old domain) ===");
    let (action2, rules2, _headers) = engine.evaluate(&context2).await;
    println!("Action: {:?}", action2);
    println!("Matched rules: {:?}", rules2);

    // Test case 3: Email from suspicious.tk (very young domain)
    let mut context3 = MailContext::default();
    context3.sender = Some("spam@suspicious.tk".to_string());
    context3.from_header = Some("spam@suspicious.tk".to_string());

    let mut headers3 = HashMap::new();
    headers3.insert(
        "from".to_string(),
        "Spam User <spam@suspicious.tk>".to_string(),
    );
    headers3.insert("reply-to".to_string(), "noreply@suspicious.tk".to_string());
    context3.headers = headers3;

    println!("\n=== Test Case 3: suspicious.tk (very young domain with suspicious TLD) ===");
    let (action3, rules3, _headers) = engine.evaluate(&context3).await;
    println!("Action: {:?}", action3);
    println!("Matched rules: {:?}", rules3);

    // Test case 4: Email from newdomain.info (45 days old)
    let mut context4 = MailContext::default();
    context4.sender = Some("user@newdomain.info".to_string());
    context4.from_header = Some("user@newdomain.info".to_string());

    let mut headers4 = HashMap::new();
    headers4.insert("from".to_string(), "User <user@newdomain.info>".to_string());
    context4.headers = headers4;

    println!("\n=== Test Case 4: newdomain.info (45 days old) ===");
    let (action4, rules4, _headers) = engine.evaluate(&context4).await;
    println!("Action: {:?}", action4);
    println!("Matched rules: {:?}", rules4);

    println!("\n=== Domain Age Testing Complete ===");
    Ok(())
}
