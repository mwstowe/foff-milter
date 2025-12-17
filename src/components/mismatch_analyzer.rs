//! Mismatch Analyzer Component
//! 
//! Consolidates all sender/domain/link/content alignment checks into
//! a single component for comprehensive mismatch detection.

use crate::components::{AnalysisComponent, ComponentAction, ComponentResult};
use crate::MailContext;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MismatchAnalysis {
    pub sender_mismatches: Vec<SenderMismatch>,
    pub domain_mismatches: Vec<DomainMismatch>,
    pub link_mismatches: Vec<LinkMismatch>,
    pub content_mismatches: Vec<ContentMismatch>,
    pub total_mismatch_score: i32,
    pub risk_level: MismatchRiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderMismatch {
    pub mismatch_type: String,
    pub description: String,
    pub severity: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainMismatch {
    pub claimed_domain: String,
    pub actual_domain: String,
    pub mismatch_type: String,
    pub severity: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkMismatch {
    pub display_text: String,
    pub actual_url: String,
    pub mismatch_type: String,
    pub severity: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMismatch {
    pub claimed_organization: String,
    pub sender_domain: String,
    pub mismatch_type: String,
    pub severity: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MismatchRiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

pub struct MismatchAnalyzer {
    brand_patterns: Vec<Regex>,
    suspicious_link_patterns: Vec<Regex>,
}

impl MismatchAnalyzer {
    pub fn new() -> Self {
        let brand_patterns = vec![
            Regex::new(r"(?i)\b(paypal|amazon|microsoft|google|apple|netflix)\b").unwrap(),
            Regex::new(r"(?i)\b(walmart|target|bestbuy|costco|ebay)\b").unwrap(),
            Regex::new(r"(?i)\b(chase|bank\s+of\s+america|wells\s+fargo|citi)\b").unwrap(),
        ];

        let suspicious_link_patterns = vec![
            Regex::new(r"(?i)(click\s+here|verify\s+now|update\s+account)").unwrap(),
            Regex::new(r"(?i)(urgent|immediate|expires\s+today)").unwrap(),
        ];

        Self {
            brand_patterns,
            suspicious_link_patterns,
        }
    }

    /// Comprehensive mismatch analysis
    pub fn analyze_mismatches(&self, context: &MailContext) -> MismatchAnalysis {
        let sender_mismatches = self.analyze_sender_mismatches(context);
        let domain_mismatches = self.analyze_domain_mismatches(context);
        let link_mismatches = self.analyze_link_mismatches(context);
        let content_mismatches = self.analyze_content_mismatches(context);

        let total_mismatch_score = self.calculate_total_score(
            &sender_mismatches,
            &domain_mismatches,
            &link_mismatches,
            &content_mismatches,
        );

        let risk_level = self.determine_risk_level(total_mismatch_score);

        MismatchAnalysis {
            sender_mismatches,
            domain_mismatches,
            link_mismatches,
            content_mismatches,
            total_mismatch_score,
            risk_level,
        }
    }

    /// Analyze sender alignment mismatches
    fn analyze_sender_mismatches(&self, context: &MailContext) -> Vec<SenderMismatch> {
        let mut mismatches = Vec::new();

        // Check envelope sender vs From header
        if let (Some(envelope_sender), Some(from_header)) = 
            (&context.sender, context.headers.get("From")) {
            
            let envelope_domain = envelope_sender.split('@').nth(1).unwrap_or("");
            
            // Extract domain from From header
            if let Some(from_domain) = self.extract_domain_from_header(from_header) {
                if envelope_domain != from_domain && !self.is_legitimate_forwarding(envelope_domain, &from_domain) {
                    mismatches.push(SenderMismatch {
                        mismatch_type: "Envelope-From Domain Mismatch".to_string(),
                        description: format!("Envelope: {} vs From: {}", envelope_domain, from_domain),
                        severity: 50,
                    });
                }
            }
        }

        // Check Reply-To vs From alignment
        if let (Some(from_header), Some(reply_to)) = 
            (context.headers.get("From"), context.headers.get("Reply-To")) {
            
            if let (Some(from_domain), Some(reply_domain)) = 
                (self.extract_domain_from_header(from_header), self.extract_domain_from_header(reply_to)) {
                
                if from_domain != reply_domain && !self.is_legitimate_forwarding(&from_domain, &reply_domain) {
                    mismatches.push(SenderMismatch {
                        mismatch_type: "From-ReplyTo Domain Mismatch".to_string(),
                        description: format!("From: {} vs Reply-To: {}", from_domain, reply_domain),
                        severity: 30,
                    });
                }
            }
        }

        mismatches
    }

    /// Analyze domain-related mismatches
    fn analyze_domain_mismatches(&self, context: &MailContext) -> Vec<DomainMismatch> {
        let mut mismatches = Vec::new();

        // Check for brand impersonation
        if let Some(from_header) = context.headers.get("From") {
            for brand_pattern in &self.brand_patterns {
                if brand_pattern.is_match(from_header) {
                    if let Some(actual_domain) = self.extract_domain_from_header(from_header) {
                        // Check if domain matches the claimed brand
                        let brand_match = brand_pattern.find(from_header).unwrap().as_str();
                        if !actual_domain.contains(&brand_match.to_lowercase()) {
                            mismatches.push(DomainMismatch {
                                claimed_domain: brand_match.to_string(),
                                actual_domain: actual_domain.clone(),
                                mismatch_type: "Brand Impersonation".to_string(),
                                severity: 100,
                            });
                        }
                    }
                }
            }
        }

        mismatches
    }

    /// Analyze link-related mismatches
    fn analyze_link_mismatches(&self, context: &MailContext) -> Vec<LinkMismatch> {
        let mut mismatches = Vec::new();

        // Simple link analysis - would be more sophisticated in practice
        if let Some(body) = &context.body {
            // Look for suspicious link patterns
            for pattern in &self.suspicious_link_patterns {
                if pattern.is_match(body) {
                    if let Some(match_text) = pattern.find(body) {
                        mismatches.push(LinkMismatch {
                            display_text: match_text.as_str().to_string(),
                            actual_url: "Unknown".to_string(), // Would extract actual URLs
                            mismatch_type: "Suspicious Link Text".to_string(),
                            severity: 25,
                        });
                    }
                }
            }
        }

        mismatches
    }

    /// Analyze content-organization mismatches
    fn analyze_content_mismatches(&self, context: &MailContext) -> Vec<ContentMismatch> {
        let mut mismatches = Vec::new();

        // Check for organization claims vs sender domain
        if let (Some(subject), Some(sender)) = (context.headers.get("Subject"), &context.sender) {
            let sender_domain = sender.split('@').nth(1).unwrap_or("");
            
            // Look for organization claims in subject
            for brand_pattern in &self.brand_patterns {
                if brand_pattern.is_match(subject) {
                    let brand_match = brand_pattern.find(subject).unwrap().as_str();
                    if !sender_domain.contains(&brand_match.to_lowercase()) {
                        mismatches.push(ContentMismatch {
                            claimed_organization: brand_match.to_string(),
                            sender_domain: sender_domain.to_string(),
                            mismatch_type: "Subject-Sender Organization Mismatch".to_string(),
                            severity: 75,
                        });
                    }
                }
            }
        }

        mismatches
    }

    fn calculate_total_score(&self, 
        sender: &[SenderMismatch],
        domain: &[DomainMismatch], 
        link: &[LinkMismatch],
        content: &[ContentMismatch]
    ) -> i32 {
        let sender_score: i32 = sender.iter().map(|m| m.severity).sum();
        let domain_score: i32 = domain.iter().map(|m| m.severity).sum();
        let link_score: i32 = link.iter().map(|m| m.severity).sum();
        let content_score: i32 = content.iter().map(|m| m.severity).sum();

        sender_score + domain_score + link_score + content_score
    }

    fn determine_risk_level(&self, total_score: i32) -> MismatchRiskLevel {
        match total_score {
            ..=0 => MismatchRiskLevel::None,
            1..=25 => MismatchRiskLevel::Low,
            26..=75 => MismatchRiskLevel::Medium,
            76..=150 => MismatchRiskLevel::High,
            151.. => MismatchRiskLevel::Critical,
        }
    }

    // Helper methods
    fn extract_domain_from_header(&self, header: &str) -> Option<String> {
        // Extract email from header like "Name <email@domain.com>"
        if let Some(start) = header.rfind('<') {
            if let Some(end) = header.rfind('>') {
                let email = &header[start + 1..end];
                return email.split('@').nth(1).map(|s| s.to_string());
            }
        }
        
        // Try direct email extraction
        if header.contains('@') {
            return header.split('@').nth(1).map(|s| s.trim().to_string());
        }
        
        None
    }

    fn is_legitimate_forwarding(&self, domain1: &str, domain2: &str) -> bool {
        // Check for known legitimate forwarding patterns
        let forwarding_pairs = [
            ("google.com", "gmail.com"),
            ("microsoft.com", "outlook.com"),
            ("amazonses.com", "amazon.com"),
        ];

        forwarding_pairs.iter().any(|(d1, d2)| {
            (domain1.contains(d1) && domain2.contains(d2)) ||
            (domain1.contains(d2) && domain2.contains(d1))
        })
    }
}

impl AnalysisComponent for MismatchAnalyzer {
    fn analyze(&self, context: &MailContext) -> ComponentResult {
        let analysis = self.analyze_mismatches(context);
        
        let action = match analysis.risk_level {
            MismatchRiskLevel::None => ComponentAction::Continue,
            MismatchRiskLevel::Low => ComponentAction::Continue,
            MismatchRiskLevel::Medium => ComponentAction::Continue,
            MismatchRiskLevel::High => ComponentAction::Tag,
            MismatchRiskLevel::Critical => ComponentAction::Reject,
        };

        let mut evidence = Vec::new();
        evidence.extend(analysis.sender_mismatches.iter().map(|m| m.description.clone()));
        evidence.extend(analysis.domain_mismatches.iter().map(|m| 
            format!("{}: {} vs {}", m.mismatch_type, m.claimed_domain, m.actual_domain)
        ));
        evidence.extend(analysis.link_mismatches.iter().map(|m| m.mismatch_type.clone()));
        evidence.extend(analysis.content_mismatches.iter().map(|m| m.mismatch_type.clone()));

        if evidence.is_empty() {
            evidence.push("No mismatches detected".to_string());
        }

        ComponentResult {
            component_name: "MismatchAnalyzer".to_string(),
            score: analysis.total_mismatch_score,
            confidence: match analysis.risk_level {
                MismatchRiskLevel::None => 0.95,
                MismatchRiskLevel::Low => 0.70,
                MismatchRiskLevel::Medium => 0.80,
                MismatchRiskLevel::High => 0.90,
                MismatchRiskLevel::Critical => 0.95,
            },
            evidence,
            action_recommended: Some(action),
        }
    }

    fn name(&self) -> &str {
        "MismatchAnalyzer"
    }

    fn priority(&self) -> u8 {
        15 // High priority - critical for security
    }
}

impl Default for MismatchAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
