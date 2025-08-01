#![allow(clippy::uninlined_format_args)]

use foff_milter::domain_age::DomainAgeChecker;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    println!("Testing REAL WHOIS lookups (not mock data)...");

    // Create checker with real WHOIS lookups (use_mock = false)
    let checker = DomainAgeChecker::new(10, false);

    let test_domains = vec![
        ("google.com", 365),   // Very old domain, should not be young
        ("example.com", 365),  // Old domain, should not be young
        ("github.com", 365),   // Relatively old, should not be young
        ("psybook.info", 365), // The spam domain, might be young
    ];

    for (domain, threshold) in test_domains {
        println!(
            "\n=== Testing domain: {} (threshold: {} days) ===",
            domain, threshold
        );

        match checker.is_domain_young(domain, threshold).await {
            Ok(is_young) => {
                println!("✅ Success!");
                println!("  Domain: {}", domain);
                println!("  Is young (< {} days): {}", threshold, is_young);

                if is_young {
                    println!("  🚨 This domain would be flagged as young!");
                } else {
                    println!("  ✅ This domain is considered established.");
                }
            }
            Err(e) => {
                println!("❌ Failed to check domain age: {}", e);
                println!("  This could be due to:");
                println!("    - WHOIS API rate limits");
                println!("    - Network connectivity issues");
                println!("    - Domain doesn't exist");
                println!("    - WHOIS service unavailable");
            }
        }
    }

    println!("\n=== Testing Domain Extraction ===");
    let test_emails = vec![
        "user@google.com",
        "test@psybook.info",
        "spam@suspicious.tk",
        "invalid-email",
    ];

    for email in test_emails {
        if let Some(domain) = DomainAgeChecker::extract_domain(email) {
            println!("✅ {} → {}", email, domain);
        } else {
            println!("❌ {} → (invalid email)", email);
        }
    }

    Ok(())
}
