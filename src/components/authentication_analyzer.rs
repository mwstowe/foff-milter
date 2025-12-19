//! Authentication Analyzer Component
//!
//! Consolidates all DKIM, SPF, and DMARC validation into a single component
//! that runs before content analysis.

use crate::components::{AnalysisComponent, ComponentAction, ComponentResult};
use crate::MailContext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResults {
    pub dkim_status: DkimStatus,
    pub spf_status: SpfStatus,
    pub dmarc_status: DmarcStatus,
    pub overall_score: i32,
    pub trust_level: AuthTrustLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DkimStatus {
    Pass,
    Fail,
    None,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpfStatus {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DmarcStatus {
    Pass,
    Fail,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthTrustLevel {
    High,   // All auth passes
    Medium, // Some auth passes
    Low,    // Minimal auth
    None,   // No auth
}

pub struct AuthenticationAnalyzer {
    // Note: DkimVerifier doesn't have a new() method, so we'll use a unit struct approach
}

impl AuthenticationAnalyzer {
    pub fn new() -> Self {
        Self {
            // DkimVerifier is a unit struct, we'll handle DKIM verification differently
        }
    }

    /// Perform complete authentication analysis
    pub fn analyze_authentication(&self, context: &MailContext) -> AuthenticationResults {
        let dkim_status = self.analyze_dkim(context);
        let spf_status = self.analyze_spf(context);
        let dmarc_status = self.analyze_dmarc(context);

        let overall_score = self.calculate_auth_score(&dkim_status, &spf_status, &dmarc_status);
        let trust_level = self.determine_trust_level(&dkim_status, &spf_status, &dmarc_status);

        AuthenticationResults {
            dkim_status,
            spf_status,
            dmarc_status,
            overall_score,
            trust_level,
        }
    }

    fn analyze_dkim(&self, context: &MailContext) -> DkimStatus {
        // Check for forwarding headers first - forwarded emails shouldn't get DKIM credit
        if context.headers.contains_key("X-Forwarded-Encrypted")
            || context.headers.contains_key("X-Google-Smtp-Source")
        {
            return DkimStatus::None; // Forwarded email - original sender doesn't get DKIM credit
        }

        // Check for DKIM signature in headers
        if let Some(_dkim_sig) = context.headers.get("DKIM-Signature") {
            // Check authentication results
            if let Some(auth_results) = context.headers.get("Authentication-Results") {
                if auth_results.contains("dkim=pass") {
                    return DkimStatus::Pass;
                } else if auth_results.contains("dkim=fail") {
                    return DkimStatus::Fail;
                }
            }

            // If we have signature but no clear result, consider it invalid
            DkimStatus::Invalid
        } else {
            DkimStatus::None
        }
    }

    fn analyze_spf(&self, context: &MailContext) -> SpfStatus {
        if let Some(auth_results) = context.headers.get("Authentication-Results") {
            if auth_results.contains("spf=pass") {
                SpfStatus::Pass
            } else if auth_results.contains("spf=fail") {
                SpfStatus::Fail
            } else if auth_results.contains("spf=softfail") {
                SpfStatus::SoftFail
            } else if auth_results.contains("spf=neutral") {
                SpfStatus::Neutral
            } else {
                SpfStatus::None
            }
        } else {
            SpfStatus::None
        }
    }

    fn analyze_dmarc(&self, context: &MailContext) -> DmarcStatus {
        if let Some(auth_results) = context.headers.get("Authentication-Results") {
            if auth_results.contains("dmarc=pass") {
                DmarcStatus::Pass
            } else if auth_results.contains("dmarc=fail") {
                DmarcStatus::Fail
            } else {
                DmarcStatus::None
            }
        } else {
            DmarcStatus::None
        }
    }

    fn calculate_auth_score(&self, dkim: &DkimStatus, spf: &SpfStatus, dmarc: &DmarcStatus) -> i32 {
        let mut score = 0;

        // DKIM scoring
        match dkim {
            DkimStatus::Pass => score -= 50,
            DkimStatus::Fail => score += 30,
            DkimStatus::Invalid => score += 15,
            DkimStatus::None => score += 5,
        }

        // SPF scoring
        match spf {
            SpfStatus::Pass => score -= 25,
            SpfStatus::Fail => score += 20,
            SpfStatus::SoftFail => score += 10,
            SpfStatus::Neutral => score += 5,
            SpfStatus::None => score += 5,
        }

        // DMARC scoring
        match dmarc {
            DmarcStatus::Pass => score -= 30,
            DmarcStatus::Fail => score += 25,
            DmarcStatus::None => score += 0,
        }

        score
    }

    fn determine_trust_level(
        &self,
        dkim: &DkimStatus,
        spf: &SpfStatus,
        dmarc: &DmarcStatus,
    ) -> AuthTrustLevel {
        let passes = [
            matches!(dkim, DkimStatus::Pass),
            matches!(spf, SpfStatus::Pass),
            matches!(dmarc, DmarcStatus::Pass),
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        match passes {
            3 => AuthTrustLevel::High,
            2 => AuthTrustLevel::High,
            1 => AuthTrustLevel::Medium,
            0 => {
                // Check if we have any auth at all
                if matches!(dkim, DkimStatus::None)
                    && matches!(spf, SpfStatus::None)
                    && matches!(dmarc, DmarcStatus::None)
                {
                    AuthTrustLevel::None
                } else {
                    AuthTrustLevel::Low
                }
            }
            _ => AuthTrustLevel::None,
        }
    }
}

impl AnalysisComponent for AuthenticationAnalyzer {
    fn analyze(&self, context: &MailContext) -> ComponentResult {
        let auth_results = self.analyze_authentication(context);

        let action = match auth_results.trust_level {
            AuthTrustLevel::High => ComponentAction::Continue,
            AuthTrustLevel::Medium => ComponentAction::Continue,
            AuthTrustLevel::Low => ComponentAction::Continue,
            AuthTrustLevel::None => ComponentAction::Continue, // Let other components decide
        };

        ComponentResult {
            component_name: "AuthenticationAnalyzer".to_string(),
            score: auth_results.overall_score,
            confidence: match auth_results.trust_level {
                AuthTrustLevel::High => 0.95,
                AuthTrustLevel::Medium => 0.75,
                AuthTrustLevel::Low => 0.50,
                AuthTrustLevel::None => 0.25,
            },
            evidence: vec![
                format!("DKIM: {:?}", auth_results.dkim_status),
                format!("SPF: {:?}", auth_results.spf_status),
                format!("DMARC: {:?}", auth_results.dmarc_status),
                format!("Trust Level: {:?}", auth_results.trust_level),
            ],
            action_recommended: Some(action),
        }
    }

    fn name(&self) -> &str {
        "AuthenticationAnalyzer"
    }

    fn priority(&self) -> u8 {
        10 // High priority - run early
    }
}

impl Default for AuthenticationAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
