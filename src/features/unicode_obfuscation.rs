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

        // Check if we have normalized content with obfuscation indicators
        if let Some(normalized) = &context.normalized {
            let subject_obfuscation = &normalized.subject.obfuscation_indicators;
            let body_obfuscation = &normalized.body_text.obfuscation_indicators;
            
            // Count Unicode homoglyph obfuscation
            let subject_unicode_count = subject_obfuscation.iter()
                .filter(|&t| matches!(t, crate::normalization::ObfuscationTechnique::UnicodeHomoglyphs))
                .count();
            let body_unicode_count = body_obfuscation.iter()
                .filter(|&t| matches!(t, crate::normalization::ObfuscationTechnique::UnicodeHomoglyphs))
                .count();
                
            let total_unicode_obfuscation = subject_unicode_count + body_unicode_count;
            
            if total_unicode_obfuscation > 0 {
                // High penalty for Unicode obfuscation detected during normalization
                let penalty = if total_unicode_obfuscation >= 2 {
                    60 // Heavy penalty for obfuscation in both subject and body
                } else {
                    40 // Moderate penalty for obfuscation in one area
                };

                score += penalty;
                evidence.push(format!(
                    "Unicode obfuscation detected during normalization: {} instances",
                    total_unicode_obfuscation
                ));
            }
        }

        FeatureScore {
            feature_name: self.name().to_string(),
            score,
            confidence: if score > 0 { 0.9 } else { 0.0 },
            evidence,
        }
    }

    fn name(&self) -> &str {
        "Unicode Obfuscation"
    }
}
