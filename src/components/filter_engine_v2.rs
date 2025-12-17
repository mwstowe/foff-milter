//! Simplified Filter Engine v2
//! 
//! Uses the new component architecture for cleaner, more maintainable processing.
//! This will eventually replace the existing FilterEngine.

use crate::components::{
    authentication_analyzer::AuthenticationAnalyzer,
    context_analyzer_v2::ContextAnalyzerV2,
    decision_engine::{DecisionConfig, DecisionEngine},
    early_decision_engine::EarlyDecisionEngine,
    email_normalizer_v2::EmailNormalizerV2,
    mismatch_analyzer::MismatchAnalyzer,
    AnalysisComponent, ComponentResult,
};
use crate::heuristic_config::Action;
use crate::MailContext;

pub struct FilterEngineV2 {
    // New simplified components
    normalizer: EmailNormalizerV2,
    early_decision: EarlyDecisionEngine,
    auth_analyzer: AuthenticationAnalyzer,
    context_analyzer: ContextAnalyzerV2,
    mismatch_analyzer: MismatchAnalyzer,
    decision_engine: DecisionEngine,
    
    // Component processing order (by priority)
    components: Vec<Box<dyn AnalysisComponent>>,
}

impl FilterEngineV2 {
    pub fn new() -> Self {
        let normalizer = EmailNormalizerV2::new();
        let early_decision = EarlyDecisionEngine::new();
        let auth_analyzer = AuthenticationAnalyzer::new();
        let context_analyzer = ContextAnalyzerV2::new();
        let mismatch_analyzer = MismatchAnalyzer::new();
        let decision_engine = DecisionEngine::default();

        // Create ordered component list (by priority)
        let mut components: Vec<Box<dyn AnalysisComponent>> = vec![
            Box::new(EarlyDecisionEngine::new()),      // Priority 5
            Box::new(AuthenticationAnalyzer::new()),   // Priority 10  
            Box::new(MismatchAnalyzer::new()),         // Priority 15
            Box::new(ContextAnalyzerV2::new()),        // Priority 20
        ];

        // Sort by priority (lower number = higher priority)
        components.sort_by_key(|c| c.priority());

        Self {
            normalizer,
            early_decision,
            auth_analyzer,
            context_analyzer,
            mismatch_analyzer,
            decision_engine,
            components,
        }
    }

    /// Simplified evaluation using new component architecture
    pub async fn evaluate_v2(&self, context: &MailContext) -> (Action, Vec<String>, Vec<(String, String)>) {
        // Phase 1: Normalization (always first)
        let normalized_email = self.normalizer.normalize_complete_email(context);
        
        // Phase 2: Component Analysis (in priority order)
        let mut component_results = Vec::new();
        
        for component in &self.components {
            let result = component.analyze(context);
            
            // Check for early exit recommendations
            if let Some(action) = &result.action_recommended {
                match action {
                    crate::components::ComponentAction::Accept => {
                        if result.confidence > 0.9 && result.score < -100 {
                            return self.build_response(Action::Accept, vec![result], "Early accept");
                        }
                    }
                    crate::components::ComponentAction::Reject => {
                        if result.confidence > 0.9 && result.score > 200 {
                            let action = Action::TagAsSpam {
                                header_name: "X-Spam-Flag".to_string(),
                                header_value: "YES".to_string(),
                            };
                            return self.build_response(action, vec![result], "Early reject");
                        }
                    }
                    _ => {}
                }
            }
            
            component_results.push(result);
        }

        // Phase 3: Final Decision
        let final_decision = self.decision_engine.make_decision(&component_results);
        
        self.build_response(
            final_decision.action,
            component_results,
            &final_decision.reasoning,
        )
    }

    /// Build response in the format expected by existing code
    fn build_response(
        &self,
        action: Action,
        results: Vec<ComponentResult>,
        reasoning: &str,
    ) -> (Action, Vec<String>, Vec<(String, String)>) {
        let matched_rules: Vec<String> = results
            .iter()
            .filter(|r| r.score != 0)
            .map(|r| format!("{}: {}", r.component_name, r.evidence.join("; ")))
            .collect();

        let total_score: i32 = results.iter().map(|r| r.score).sum();

        let headers = vec![
            (
                "X-FOFF-Score-V2".to_string(),
                format!("{} - foff-milter v{} (simplified)", total_score, env!("CARGO_PKG_VERSION")),
            ),
            (
                "X-FOFF-Reasoning".to_string(),
                reasoning.to_string(),
            ),
        ];

        (action, matched_rules, headers)
    }

    /// Configure decision thresholds
    pub fn configure_thresholds(&mut self, reject_threshold: i32, spam_threshold: i32, reject_to_tag: bool) {
        let config = DecisionConfig {
            reject_threshold,
            spam_threshold,
            accept_threshold: 0,
            reject_to_tag,
        };
        self.decision_engine.update_config(config);
    }

    /// Add whitelist pattern to early decision engine
    pub fn add_whitelist_pattern(&mut self, pattern: &str) -> Result<(), regex::Error> {
        // Note: This is a simplified approach. In practice, we'd need mutable access
        // to the early decision engine or a different architecture.
        // For now, this demonstrates the interface.
        Ok(())
    }

    /// Add sender blocking pattern
    pub fn add_sender_blocking_pattern(&mut self, pattern: &str) -> Result<(), regex::Error> {
        // Similar to whitelist - would need mutable access to early decision engine
        Ok(())
    }
}

impl Default for FilterEngineV2 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_context() -> MailContext {
        let mut headers = HashMap::new();
        headers.insert("From".to_string(), "test@example.com".to_string());
        headers.insert("Subject".to_string(), "Test Email".to_string());

        MailContext {
            sender: Some("test@example.com".to_string()),
            from_header: Some("test@example.com".to_string()),
            recipients: vec!["recipient@example.com".to_string()],
            headers,
            mailer: None,
            subject: Some("Test Email".to_string()),
            hostname: None,
            helo: None,
            body: Some("Test email body".to_string()),
            last_header_name: None,
            attachments: Vec::new(),
            extracted_media_text: String::new(),
            is_legitimate_business: false,
            is_first_hop: true,
            forwarding_source: None,
            proximate_mailer: None,
            normalized: None,
            dkim_verification: None,
        }
    }

    #[tokio::test]
    async fn test_simple_evaluation() {
        let engine = FilterEngineV2::new();
        let context = create_test_context();
        
        let (action, rules, headers) = engine.evaluate_v2(&context).await;
        
        // Should have some result
        assert!(!headers.is_empty());
        assert!(headers.iter().any(|(name, _)| name == "X-FOFF-Score-V2"));
    }

    #[test]
    fn test_threshold_configuration() {
        let mut engine = FilterEngineV2::new();
        engine.configure_thresholds(400, 75, true);
        
        let config = engine.decision_engine.get_config();
        assert_eq!(config.reject_threshold, 400);
        assert_eq!(config.spam_threshold, 75);
        assert!(config.reject_to_tag);
    }
}
