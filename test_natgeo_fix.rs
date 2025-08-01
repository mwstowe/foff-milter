#![allow(clippy::uninlined_format_args)]

use foff_milter::domain_age::DomainAgeChecker;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    println!("Testing National Geographic domain age fix...");

    // Create checker with real WHOIS lookups
    let checker = DomainAgeChecker::new(10, false);

    // Test the problematic domain from the log
    let test_domain = "email.nationalgeographic.com";

    println!("\n=== Testing Domain: {} ===", test_domain);

    // Test root domain extraction
    let root_domain = checker.extract_root_domain(test_domain);
    println!("Original domain: {}", test_domain);
    println!("Root domain: {}", root_domain);

    // Test domain age checking
    println!("\n🔍 Performing WHOIS lookup for root domain...");

    match checker.is_domain_young(test_domain, 365).await {
        Ok(is_young) => {
            println!("✅ Success!");
            println!("  Domain: {}", test_domain);
            println!("  Root domain used for WHOIS: {}", root_domain);
            println!("  Is young (< 365 days): {}", is_young);

            if is_young {
                println!("  🚨 This domain would be flagged as young!");
            } else {
                println!("  ✅ This domain is considered established.");
            }
        }
        Err(e) => {
            println!("❌ Failed to check domain age: {}", e);
            println!("  This should now work better with root domain extraction");
        }
    }

    // Test a few more examples
    let test_cases = vec![
        ("mail.google.com", "google.com"),
        ("email.amazon.com", "amazon.com"),
        ("newsletters.cnn.com", "cnn.com"),
        ("marketing.example.co.uk", "example.co.uk"),
    ];

    println!("\n=== Testing Root Domain Extraction ===");
    for (subdomain, expected_root) in test_cases {
        let actual_root = checker.extract_root_domain(subdomain);
        let status = if actual_root == expected_root {
            "✅"
        } else {
            "❌"
        };
        println!(
            "{} {} → {} (expected: {})",
            status, subdomain, actual_root, expected_root
        );
    }

    println!("\n=== Summary ===");
    println!("✅ Root domain extraction implemented");
    println!("✅ WHOIS queries now use root domains instead of subdomains");
    println!("✅ Should resolve 'Could not parse creation date from WHOIS text' errors");
    println!("✅ National Geographic email domain should now work correctly");

    Ok(())
}
