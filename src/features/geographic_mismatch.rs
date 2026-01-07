use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;

pub struct GeographicMismatchAnalyzer;

impl GeographicMismatchAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl FeatureExtractor for GeographicMismatchAnalyzer {
    fn name(&self) -> &str {
        "Geographic Mismatch"
    }

    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();

        let sender_domain = context
            .from_header
            .as_deref()
            .and_then(|from| from.split('@').nth(1))
            .unwrap_or("")
            .to_lowercase();

        let content = format!(
            "{} {}",
            context.subject.as_deref().unwrap_or(""),
            context.body.as_deref().unwrap_or("")
        );

        // Chinese domains (.cn) sending Japanese content
        if sender_domain.ends_with(".cn") {
            // Check for Japanese characters (Hiragana, Katakana, Kanji)
            if content.chars().any(|c| {
                ('\u{3040}'..='\u{309F}').contains(&c) || // Hiragana
                ('\u{30A0}'..='\u{30FF}').contains(&c) || // Katakana
                ('\u{4E00}'..='\u{9FAF}').contains(&c) // CJK Unified Ideographs
            }) {
                score += 200;
                evidence.push("Chinese domain (.cn) sending Japanese content".to_string());
            }
        }

        // Russian domains (.ru) sending non-Russian content
        if sender_domain.ends_with(".ru")
            && !content
                .chars()
                .any(|c| ('\u{0400}'..='\u{04FF}').contains(&c))
        {
            score += 150;
            evidence.push("Russian domain (.ru) sending non-Russian content".to_string());
        }

        let confidence = if score > 0 { 0.95 } else { 0.1 };

        FeatureScore {
            feature_name: "Geographic Mismatch".to_string(),
            score,
            confidence,
            evidence,
        }
    }
}

impl Default for GeographicMismatchAnalyzer {
    fn default() -> Self {
        Self
    }
}
