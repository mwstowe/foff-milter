use std::collections::HashMap;
use regex::Regex;

// Simulate the decode_mime_header function
fn decode_mime_header(header_value: &str) -> String {
    // This is a simplified version - the real one handles more cases
    header_value.to_string()
}

fn main() {
    let from_header = r#"Member Adventure Support #9kz7ve" <noreply@dailydials19.onmicrosoft.com>"#;
    let pattern = r".*onmicrosoft\.com";
    
    println!("Original header: {}", from_header);
    println!("Pattern: {}", pattern);
    
    let decoded = decode_mime_header(from_header);
    println!("Decoded header: {}", decoded);
    
    let regex = Regex::new(pattern).unwrap();
    let matches = regex.is_match(&decoded);
    
    println!("Pattern matches: {}", matches);
    
    // Test what the pattern actually matches
    if let Some(captures) = regex.find(&decoded) {
        println!("Matched text: '{}'", captures.as_str());
    }
}