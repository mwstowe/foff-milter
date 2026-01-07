use super::{FeatureExtractor, FeatureScore};
use crate::MailContext;

pub struct UnicodeObfuscationAnalyzer;

impl UnicodeObfuscationAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl FeatureExtractor for UnicodeObfuscationAnalyzer {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();

        // Get the properly normalized subject and body
        let subject = if let Some(normalized) = &context.normalized {
            &normalized.subject.normalized
        } else {
            context.subject.as_deref().unwrap_or("")
        };
        
        let body = if let Some(normalized) = &context.normalized {
            &normalized.body_text.normalized
        } else {
            context.body.as_deref().unwrap_or("")
        };
        
        let combined_text = format!("{} {}", subject, body);

        // Check for Mathematical Alphanumeric Symbols (U+1D400-1D7FF)
        let mut math_unicode_count = 0;
        let mut total_chars = 0;

        for ch in combined_text.chars() {
            if ch.is_alphabetic() || ch.is_numeric() {
                total_chars += 1;
                let code_point = ch as u32;
                if (0x1D400..=0x1D7FF).contains(&code_point) {
                    math_unicode_count += 1;
                }
            }
        }

        if math_unicode_count > 0 {
            let obfuscation_ratio = (math_unicode_count as f32 / total_chars as f32) * 100.0;
            
            // High penalty for mathematical Unicode obfuscation
            let penalty = if math_unicode_count >= 5 {
                60 // Heavy penalty for extensive obfuscation
            } else if math_unicode_count >= 2 {
                40 // Moderate penalty for some obfuscation
            } else {
                20 // Light penalty for minimal obfuscation
            };

            score += penalty;
            evidence.push(format!(
                "Mathematical Unicode obfuscation detected: {} characters ({:.1}% of text)",
                math_unicode_count, obfuscation_ratio
            ));
        }

        FeatureScore {
            feature_name: self.name().to_string(),
            score,
            confidence: if math_unicode_count > 0 { 0.9 } else { 0.0 },
            evidence,
        }
    }

    fn name(&self) -> &str {
        "Unicode Obfuscation"
    }
}
