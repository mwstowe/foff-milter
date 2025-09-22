use foff_milter::filter::FilterEngine;
use foff_milter::Config;
use std::collections::HashMap;

fn main() {
    // Load the configuration
    let config = Config::from_file("hotel.yaml").expect("Failed to load config");
    let filter_engine = FilterEngine::new(config).expect("Failed to create filter engine");

    // Create test email headers for the CVS Medicare spam
    let mut headers = HashMap::new();
    
    // Authentication results
    headers.insert("authentication-results".to_string(), 
        "juliett.example.com; dkim=fail reason=\"key not found in DNS\" (0-bit key; unprotected) header.d=ml.fleetlogisticstrucks.site header.i=catili@ml.fleetlogisticstrucks.site header.b=l9fB3a0+".to_string());
    
    // From header
    headers.insert("from".to_string(), 
        "CVS - Medicare Kit <Medicare701192@fleetlogisticstrucks.site>".to_string());
    
    // Subject
    headers.insert("subject".to_string(), 
        "Re: Your Free Medicare Essentials Kit from CVS".to_string());
    
    // Reply-To
    headers.insert("reply-to".to_string(), 
        "<replyhdwpkobuiabqxgfv@tbtdrdbmqikmjciedxxmuncefn.com>".to_string());
    
    // Return-Path
    headers.insert("return-path".to_string(), 
        "<CVS1044_6873@fleetlogisticstrucks.site>".to_string());
    
    // Sender and recipient
    let sender = "CVS1044_6873@fleetlogisticstrucks.site";
    let recipients = vec!["mjohnson@example.com"];

    println!("Testing email headers:");
    println!("From: {}", headers.get("from").unwrap());
    println!("Subject: {}", headers.get("subject").unwrap());
    println!("Authentication-Results: {}", headers.get("authentication-results").unwrap());
    println!("Reply-To: {}", headers.get("reply-to").unwrap());
    println!("Sender: {}", sender);
    println!();

    // Test the filter
    match filter_engine.evaluate_email(sender, &recipients, &headers, "") {
        Ok(result) => {
            println!("Filter result: {:?}", result);
            if let Some(rule_name) = result.matched_rule {
                println!("Matched rule: {}", rule_name);
            } else {
                println!("No rule matched - email would be accepted");
            }
        }
        Err(e) => {
            println!("Error evaluating email: {}", e);
        }
    }

    // Test specific patterns manually
    println!("\n=== Manual Pattern Testing ===");
    
    // Test DKIM fail pattern
    let auth_header = headers.get("authentication-results").unwrap();
    let dkim_fail_pattern = regex::Regex::new(r"(?i)dkim=fail").unwrap();
    println!("DKIM fail pattern matches: {}", dkim_fail_pattern.is_match(auth_header));
    
    // Test CVS brand pattern
    let from_header = headers.get("from").unwrap();
    let cvs_pattern = regex::Regex::new(r"(?i).*(cvs).*").unwrap();
    println!("CVS brand pattern matches: {}", cvs_pattern.is_match(from_header));
    
    // Test exclusion pattern
    let sender_pattern = regex::Regex::new(r".*@(amazon|microsoft|apple|google|netflix|spotify|adobe|paypal|chase|wellsfargo|bankofamerica|citibank|capitalone|walmart|target|costco|homedepot|lowes|bestbuy|macys|nordstrom|cvs|walgreens|riteaid|medicare|medicaid|ssa|irs|usps|fedex|ups|dhl)\.com$").unwrap();
    println!("Exclusion pattern matches sender '{}': {}", sender, sender_pattern.is_match(sender));
    
    // Test .site TLD pattern
    let site_pattern = regex::Regex::new(r".*@.*\.(site)$").unwrap();
    println!("Site TLD pattern matches sender '{}': {}", sender, site_pattern.is_match(sender));
}
