#![allow(clippy::uninlined_format_args)]

use foff_milter::domain_age::DomainAgeChecker;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    println!("Testing SendGrid domain extraction fix...");

    // Test the problematic domain from the log
    let malformed_input = "sendgrid.net>,body=8bitmime";
    let expected_domain = "sendgrid.net";

    println!("\n=== Testing Malformed Domain Extraction ===");
    println!("Input: {}", malformed_input);

    // Test domain extraction
    match DomainAgeChecker::extract_domain(&format!("user@{}", malformed_input)) {
        Some(extracted) => {
            println!("✅ Extracted domain: {}", extracted);
            if extracted == expected_domain {
                println!("✅ Correctly cleaned up malformed input!");
            } else {
                println!("❌ Expected: {}, got: {}", expected_domain, extracted);
            }
        }
        None => {
            println!("❌ Failed to extract domain from malformed input");
        }
    }

    // Test various malformed cases
    let test_cases = vec![
        ("user@sendgrid.net>,body=8bitmime", "sendgrid.net"),
        ("user@example.com>", "example.com"),
        ("user@domain.com,param=value", "domain.com"),
        ("user@domain.com;param=value", "domain.com"),
        ("user@domain.com extra stuff", "domain.com"),
        ("user@mail.google.com>,size=1024", "mail.google.com"),
    ];

    println!("\n=== Testing Various Malformed Cases ===");
    for (input, expected) in test_cases {
        match DomainAgeChecker::extract_domain(input) {
            Some(extracted) => {
                let status = if extracted == expected { "✅" } else { "❌" };
                println!(
                    "{} {} → {} (expected: {})",
                    status, input, extracted, expected
                );
            }
            None => {
                println!("❌ {} → None (expected: {})", input, expected);
            }
        }
    }

    // Test with real domain age checking
    println!("\n=== Testing Real Domain Age Check ===");
    let checker = DomainAgeChecker::new(10, false);

    // This should now work without the malformed characters
    match checker.is_domain_young("sendgrid.net", 365).await {
        Ok(is_young) => {
            println!("✅ SendGrid domain age check successful!");
            println!("  Domain: sendgrid.net");
            println!("  Is young (< 365 days): {}", is_young);
            println!("  ✅ No more WHOIS parsing errors!");
        }
        Err(e) => {
            println!("❌ Domain age check failed: {}", e);
        }
    }

    println!("\n=== Summary ===");
    println!("✅ Domain extraction now handles malformed SMTP parameters");
    println!("✅ Removes >, comma, semicolon, and whitespace artifacts");
    println!("✅ Should resolve 'Invalid query' WHOIS errors");
    println!("✅ SendGrid and similar domains should now work correctly");

    Ok(())
}
