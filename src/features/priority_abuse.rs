use crate::features::{get_header_case_insensitive, FeatureExtractor, FeatureScore};
use crate::MailContext;

pub struct PriorityAbuseFeature;

impl Default for PriorityAbuseFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl PriorityAbuseFeature {
    pub fn new() -> Self {
        PriorityAbuseFeature
    }
}

impl FeatureExtractor for PriorityAbuseFeature {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();

        // Check for priority header abuse
        let has_high_priority = get_header_case_insensitive(&context.headers, "X-Priority")
            .map(|v| v.contains("1"))
            .unwrap_or(false)
            || get_header_case_insensitive(&context.headers, "Priority")
                .map(|v| v.to_lowercase().contains("urgent"))
                .unwrap_or(false);

        if has_high_priority {
            // Check if this looks like marketing content
            let is_marketing = context
                .subject
                .as_ref()
                .map(|s| {
                    let s_lower = s.to_lowercase();
                    s_lower.contains("hack")
                        || s_lower.contains("secret")
                        || s_lower.contains("destroy")
                        || s_lower.contains("kills")
                        || s_lower.contains("unbelievable")
                        || s_lower.contains("incredible")
                })
                .unwrap_or(false);

            if is_marketing {
                score += 50;
                evidence.push("High priority headers used with marketing content".to_string());
            }
        }

        FeatureScore {
            feature_name: "priority_abuse".to_string(),
            score,
            confidence: if score > 0 { 0.8 } else { 0.0 },
            evidence,
        }
    }

    fn name(&self) -> &str {
        "priority_abuse"
    }
}
