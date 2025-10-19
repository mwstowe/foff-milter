pub mod suspicious_domains;

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub matched: bool,
    pub confidence: u32,
    pub reason: String,
    pub rule_name: String,
}

impl DetectionResult {
    pub fn new(matched: bool, confidence: u32, reason: String, rule_name: String) -> Self {
        Self {
            matched,
            confidence,
            reason,
            rule_name,
        }
    }

    pub fn no_match(rule_name: String) -> Self {
        Self {
            matched: false,
            confidence: 0,
            reason: "No match".to_string(),
            rule_name,
        }
    }
}
