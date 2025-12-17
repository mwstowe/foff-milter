//! Early Decision Engine Component
//! 
//! Consolidates all early exit logic into a single component with clear precedence.
//! Handles: Same-server → Upstream → Sender-blocking → Whitelist → Blocklist

use crate::components::{AnalysisComponent, ComponentAction, ComponentResult};
use crate::MailContext;
use regex::Regex;

pub struct EarlyDecisionEngine {
    sender_blocking_patterns: Vec<Regex>,
    whitelist_domains: Vec<String>,
    whitelist_patterns: Vec<Regex>,
    blocklist_domains: Vec<String>,
    blocklist_patterns: Vec<Regex>,
}

#[derive(Debug, Clone)]
pub enum EarlyDecision {
    SameServer,
    UpstreamTrust,
    SenderBlocked(String),
    Whitelisted(String),
    Blocklisted(String),
    Continue,
}

impl EarlyDecisionEngine {
    pub fn new() -> Self {
        Self {
            sender_blocking_patterns: Vec::new(),
            whitelist_domains: Vec::new(),
            whitelist_patterns: Vec::new(),
            blocklist_domains: Vec::new(),
            blocklist_patterns: Vec::new(),
        }
    }

    /// Add sender blocking pattern
    pub fn add_sender_blocking_pattern(&mut self, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.sender_blocking_patterns.push(regex);
        Ok(())
    }

    /// Add whitelist domain
    pub fn add_whitelist_domain(&mut self, domain: &str) {
        self.whitelist_domains.push(domain.to_string());
    }

    /// Add whitelist pattern
    pub fn add_whitelist_pattern(&mut self, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.whitelist_patterns.push(regex);
        Ok(())
    }

    /// Add blocklist domain
    pub fn add_blocklist_domain(&mut self, domain: &str) {
        self.blocklist_domains.push(domain.to_string());
    }

    /// Add blocklist pattern
    pub fn add_blocklist_pattern(&mut self, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.blocklist_patterns.push(regex);
        Ok(())
    }

    /// Make early decision with clear precedence order
    pub fn make_early_decision(&self, context: &MailContext) -> EarlyDecision {
        // 1. Same server check (highest priority)
        if self.is_same_server_email(context) {
            return EarlyDecision::SameServer;
        }

        // 2. Upstream trust check
        if self.has_upstream_trust(context) {
            return EarlyDecision::UpstreamTrust;
        }

        // 3. Sender blocking check
        if let Some(blocked_reason) = self.check_sender_blocking(context) {
            return EarlyDecision::SenderBlocked(blocked_reason);
        }

        // 4. Whitelist check
        if let Some(whitelist_reason) = self.check_whitelist(context) {
            return EarlyDecision::Whitelisted(whitelist_reason);
        }

        // 5. Blocklist check
        if let Some(blocklist_reason) = self.check_blocklist(context) {
            return EarlyDecision::Blocklisted(blocklist_reason);
        }

        // 6. Continue to full analysis
        EarlyDecision::Continue
    }

    fn is_same_server_email(&self, context: &MailContext) -> bool {
        // Check for X-FOFF headers indicating same server processing
        context.headers.keys().any(|key| {
            key.to_lowercase().starts_with("x-foff")
        })
    }

    fn has_upstream_trust(&self, context: &MailContext) -> bool {
        // Check for upstream FOFF-milter processing indicators
        if let Some(auth_results) = context.headers.get("Authentication-Results") {
            auth_results.contains("foff-milter")
        } else {
            false
        }
    }

    fn check_sender_blocking(&self, context: &MailContext) -> Option<String> {
        let sender = context.sender.as_ref()?;
        
        // Check against blocking patterns
        for pattern in &self.sender_blocking_patterns {
            if pattern.is_match(sender) {
                return Some(format!("Sender pattern blocked: {}", pattern.as_str()));
            }
        }

        None
    }

    fn check_whitelist(&self, context: &MailContext) -> Option<String> {
        // Check sender domain against whitelist
        if let Some(sender) = &context.sender {
            if let Some(domain) = sender.split('@').nth(1) {
                if self.whitelist_domains.contains(&domain.to_string()) {
                    return Some(format!("Whitelisted domain: {}", domain));
                }

                // Check against whitelist patterns
                for pattern in &self.whitelist_patterns {
                    if pattern.is_match(sender) {
                        return Some(format!("Whitelisted pattern: {}", pattern.as_str()));
                    }
                }
            }
        }

        // Check From header
        if let Some(from_header) = context.headers.get("From") {
            for pattern in &self.whitelist_patterns {
                if pattern.is_match(from_header) {
                    return Some(format!("Whitelisted From header: {}", pattern.as_str()));
                }
            }
        }

        None
    }

    fn check_blocklist(&self, context: &MailContext) -> Option<String> {
        // Check sender domain against blocklist
        if let Some(sender) = &context.sender {
            if let Some(domain) = sender.split('@').nth(1) {
                if self.blocklist_domains.contains(&domain.to_string()) {
                    return Some(format!("Blocklisted domain: {}", domain));
                }

                // Check against blocklist patterns
                for pattern in &self.blocklist_patterns {
                    if pattern.is_match(sender) {
                        return Some(format!("Blocklisted pattern: {}", pattern.as_str()));
                    }
                }
            }
        }

        None
    }
}

impl AnalysisComponent for EarlyDecisionEngine {
    fn analyze(&self, context: &MailContext) -> ComponentResult {
        let decision = self.make_early_decision(context);
        
        let (action, score, evidence) = match &decision {
            EarlyDecision::SameServer => (
                ComponentAction::Accept,
                -1000, // Strong negative score
                vec!["Same server email detected".to_string()]
            ),
            EarlyDecision::UpstreamTrust => (
                ComponentAction::Accept,
                -500,
                vec!["Upstream FOFF-milter trust".to_string()]
            ),
            EarlyDecision::SenderBlocked(reason) => (
                ComponentAction::Reject,
                1000, // Strong positive score
                vec![reason.clone()]
            ),
            EarlyDecision::Whitelisted(reason) => (
                ComponentAction::Accept,
                -200,
                vec![reason.clone()]
            ),
            EarlyDecision::Blocklisted(reason) => (
                ComponentAction::Reject,
                500,
                vec![reason.clone()]
            ),
            EarlyDecision::Continue => (
                ComponentAction::Continue,
                0,
                vec!["No early decision - continue analysis".to_string()]
            ),
        };

        ComponentResult {
            component_name: "EarlyDecisionEngine".to_string(),
            score,
            confidence: match decision {
                EarlyDecision::Continue => 0.0,
                _ => 1.0, // Early decisions are definitive
            },
            evidence,
            action_recommended: Some(action),
        }
    }

    fn name(&self) -> &str {
        "EarlyDecisionEngine"
    }

    fn priority(&self) -> u8 {
        5 // Highest priority - run first
    }
}

impl Default for EarlyDecisionEngine {
    fn default() -> Self {
        Self::new()
    }
}
