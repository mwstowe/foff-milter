//! Context Analyzer v2 Component
//! 
//! Consolidates trust_analyzer, business_analyzer, and seasonal_analyzer
//! into a single unified component with simplified scoring.

use crate::components::{AnalysisComponent, ComponentAction, ComponentResult};
use crate::MailContext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextAnalysis {
    pub trust_score: i32,
    pub business_score: i32,
    pub temporal_score: i32,
    pub overall_score: i32,
    pub context_level: ContextLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContextLevel {
    Trusted,    // High trust, established business
    Neutral,    // Normal email patterns
    Suspicious, // Some concerning patterns
    Untrusted,  // Multiple red flags
}

pub struct ContextAnalyzerV2;

impl ContextAnalyzerV2 {
    pub fn new() -> Self {
        Self
    }

    /// Unified context analysis combining trust, business, and temporal factors
    pub fn analyze_context(&self, context: &MailContext) -> ContextAnalysis {
        let trust_score = self.analyze_trust(context);
        let business_score = self.analyze_business_legitimacy(context);
        let temporal_score = self.analyze_temporal_patterns(context);

        let overall_score = trust_score + business_score + temporal_score;
        let context_level = self.determine_context_level(overall_score);

        ContextAnalysis {
            trust_score,
            business_score,
            temporal_score,
            overall_score,
            context_level,
        }
    }

    /// Analyze domain and authentication trust factors
    fn analyze_trust(&self, context: &MailContext) -> i32 {
        let mut score = 0;

        // Authentication trust
        if let Some(auth_results) = context.headers.get("Authentication-Results") {
            if auth_results.contains("dkim=pass") {
                score -= 25;
            }
            if auth_results.contains("spf=pass") {
                score -= 15;
            }
            if auth_results.contains("dmarc=pass") {
                score -= 20;
            }
        }

        // Infrastructure trust
        if let Some(sender) = &context.sender {
            if let Some(domain) = sender.split('@').nth(1) {
                // Established domains get trust bonus
                if self.is_established_domain(domain) {
                    score -= 30;
                }
                
                // Free email providers are neutral
                if self.is_free_email_provider(domain) {
                    score += 5;
                }
            }
        }

        score
    }

    /// Analyze business legitimacy indicators
    fn analyze_business_legitimacy(&self, context: &MailContext) -> i32 {
        let mut score = 0;

        // Professional communication patterns
        if self.has_professional_patterns(context) {
            score -= 20;
        }

        // Unsubscribe headers indicate legitimate bulk email
        if context.headers.contains_key("List-Unsubscribe") {
            score -= 15;
        }

        // Business domain patterns
        if let Some(sender) = &context.sender {
            if self.has_business_domain_pattern(sender) {
                score -= 10;
            }
        }

        score
    }

    /// Analyze temporal and behavioral patterns
    fn analyze_temporal_patterns(&self, context: &MailContext) -> i32 {
        let mut score = 0;

        // Check for suspicious timing patterns (simplified)
        if let Some(date_header) = context.headers.get("Date") {
            if self.has_suspicious_timing(date_header) {
                score += 15;
            }
        }

        // Check for burst patterns in message ID
        if let Some(message_id) = context.headers.get("Message-ID") {
            if self.has_burst_patterns(message_id) {
                score += 10;
            }
        }

        score
    }

    fn determine_context_level(&self, overall_score: i32) -> ContextLevel {
        match overall_score {
            ..=-50 => ContextLevel::Trusted,
            -49..=-10 => ContextLevel::Neutral,
            -9..=20 => ContextLevel::Suspicious,
            21.. => ContextLevel::Untrusted,
        }
    }

    // Helper methods (simplified implementations)
    fn is_established_domain(&self, domain: &str) -> bool {
        matches!(domain, 
            "amazon.com" | "google.com" | "microsoft.com" | "apple.com" |
            "netflix.com" | "walmart.com" | "target.com" | "paypal.com"
        )
    }

    fn is_free_email_provider(&self, domain: &str) -> bool {
        matches!(domain,
            "gmail.com" | "yahoo.com" | "hotmail.com" | "outlook.com" |
            "aol.com" | "icloud.com"
        )
    }

    fn has_professional_patterns(&self, context: &MailContext) -> bool {
        // Check for professional language patterns
        if let Some(subject) = context.headers.get("Subject") {
            let professional_terms = ["invoice", "receipt", "statement", "notification", "update"];
            return professional_terms.iter().any(|term| 
                subject.to_lowercase().contains(term)
            );
        }
        false
    }

    fn has_business_domain_pattern(&self, sender: &str) -> bool {
        // Simple business domain pattern check
        sender.contains("noreply") || sender.contains("no-reply") || 
        sender.contains("support") || sender.contains("info")
    }

    fn has_suspicious_timing(&self, _date_header: &str) -> bool {
        // Simplified - would normally parse date and check for odd hours
        false
    }

    fn has_burst_patterns(&self, message_id: &str) -> bool {
        // Check for excessive numbers indicating automated generation
        let digit_count = message_id.chars().filter(|c| c.is_ascii_digit()).count();
        digit_count > 15
    }
}

impl AnalysisComponent for ContextAnalyzerV2 {
    fn analyze(&self, context: &MailContext) -> ComponentResult {
        let analysis = self.analyze_context(context);
        
        let action = match analysis.context_level {
            ContextLevel::Trusted => ComponentAction::Continue, // Strong positive signal
            ContextLevel::Neutral => ComponentAction::Continue,
            ContextLevel::Suspicious => ComponentAction::Continue, // Let other components decide
            ContextLevel::Untrusted => ComponentAction::Continue, // Contribute to scoring but don't decide alone
        };

        ComponentResult {
            component_name: "ContextAnalyzerV2".to_string(),
            score: analysis.overall_score,
            confidence: match analysis.context_level {
                ContextLevel::Trusted => 0.85,
                ContextLevel::Neutral => 0.50,
                ContextLevel::Suspicious => 0.70,
                ContextLevel::Untrusted => 0.80,
            },
            evidence: vec![
                format!("Trust Score: {}", analysis.trust_score),
                format!("Business Score: {}", analysis.business_score),
                format!("Temporal Score: {}", analysis.temporal_score),
                format!("Context Level: {:?}", analysis.context_level),
            ],
            action_recommended: Some(action),
        }
    }

    fn name(&self) -> &str {
        "ContextAnalyzerV2"
    }

    fn priority(&self) -> u8 {
        20 // Medium priority - provides context for other components
    }
}

impl Default for ContextAnalyzerV2 {
    fn default() -> Self {
        Self::new()
    }
}
