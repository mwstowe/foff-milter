pub mod authentication_analysis;
pub mod brand_impersonation;
pub mod context_analyzer;
pub mod domain_business_mismatch;
pub mod domain_reputation;
pub mod esp_validation;
pub mod financial_validation;
pub mod health_spam;
pub mod invoice_analyzer;
pub mod link_analyzer;
pub mod portuguese_language;
pub mod priority_abuse;
pub mod product_spam;
pub mod sender_alignment;
pub mod server_role_analyzer;
pub mod system_blocklist;
pub mod tld_risk;
pub mod unicode_obfuscation;

use crate::MailContext;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Case-insensitive header lookup utility function
pub fn get_header_case_insensitive<'a>(
    headers: &'a HashMap<String, String>,
    header_name: &str,
) -> Option<&'a String> {
    let header_lower = header_name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == header_lower)
        .map(|(_, v)| v)
}

/// Detect a legitimate legal / class-action settlement notice.
///
/// Court-appointed settlement administrators legitimately name the defendant
/// brand in the From display name, subject, and body (e.g. "In re Amazon
/// Return Policy Litigation" sent from returnsettlement.com). Those references
/// look like brand impersonation to the heuristics, but they are a recognizable
/// legal-notice content pattern, not impersonation.
///
/// To keep a spammer from simply pasting settlement language onto a throwaway
/// domain, this requires DKIM alignment (the cryptographic identity matches the
/// claimed From domain) in addition to the legal-content signal. A settlement
/// administrator domain plus a single strong legal marker, or two independent
/// legal markers on their own, qualifies.
pub fn is_legitimate_legal_settlement_notice(context: &MailContext) -> bool {
    // Require DKIM alignment: the signing domain matches the claimed From domain.
    let dkim_aligned = context
        .dkim_verification
        .as_ref()
        .map(|d| {
            matches!(
                d.auth_status,
                crate::dkim_verification::DkimAuthStatus::Pass
            ) && matches!(
                d.domain_alignment,
                crate::dkim_verification::DomainAlignment::Aligned
            )
        })
        .unwrap_or(false);
    if !dkim_aligned {
        return false;
    }

    let subject = context.subject.as_deref().unwrap_or("").to_lowercase();
    let body = context.body.as_deref().unwrap_or("").to_lowercase();
    let hay = format!("{} {}", subject, body);

    let legal_markers = [
        "class action settlement",
        "class action lawsuit",
        "settlement administrator",
        "legal notice",
        "litigation",
        "in re ",
        "proposed settlement",
        "notice of settlement",
        "you may be entitled",
    ];
    let legal_hits = legal_markers.iter().filter(|m| hay.contains(*m)).count();

    let sender_domain = context
        .from_header
        .as_ref()
        .or(context.sender.as_ref())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let is_settlement_domain = sender_domain.contains("settlement")
        || sender_domain.contains("litigation")
        || sender_domain.contains("classaction")
        || sender_domain.contains("administration");

    legal_hits >= 2 || (legal_hits >= 1 && is_settlement_domain)
}

/// Recognize a DKIM-authenticated *organizational* identity delivered via a
/// recognized ESP, even when the From header domain differs from the signing
/// domain.
///
/// Some large brands send through an ESP (e.g. Salesforce Marketing Cloud) with
/// a CDN/Akamai-fronted From domain, while the DKIM signature and the envelope
/// Return-Path both belong to the brand's real registrable domain. Example
/// (Travelers Insurance):
///   From:         "Travelers Insurance" <reply@e7269.dscx.akamaiedge.net>
///   DKIM d=:      email.travelers.com (+ s1.y.mc.salesforce.com)
///   Return-Path:  bounce-...@bounce.email.travelers.com
///   Received:     mta.email.travelers.com (Salesforce/ExactTarget)
/// Here the From domain (akamaiedge.net) is not the organization, but the
/// cryptographically-signed identity (travelers.com) matches the envelope
/// return path, and delivery is through a recognized ESP. The message is
/// authentically from the organization; feature checks that penalize the From
/// domain for not aligning with the Return-Path/Sender are false positives.
///
/// This is deliberately a *conjunction* — DKIM pass AND signing-domain /
/// Return-Path registrable-domain match AND trusted ESP. DKIM alignment alone
/// is NOT sufficient: a spammer can self-sign a throwaway domain and set a
/// matching Return-Path. Requiring recognized ESP infrastructure is what makes
/// this safe, mirroring the trusted-ESP gate used elsewhere in the codebase.
pub fn is_dkim_authenticated_org_identity(context: &MailContext) -> bool {
    let dkim = match context.dkim_verification.as_ref() {
        Some(d) => d,
        None => return false,
    };

    // 1. DKIM must pass.
    if !matches!(
        dkim.auth_status,
        crate::dkim_verification::DkimAuthStatus::Pass
    ) {
        return false;
    }

    // 2. Some DKIM signing domain must share the registrable (organizational)
    //    domain of the envelope Return-Path. This ties the cryptographic
    //    identity to the envelope originator rather than to the (possibly
    //    CDN-fronted) From header.
    let return_path = get_header_case_insensitive(&context.headers, "return-path")
        .or_else(|| get_header_case_insensitive(&context.headers, "Return-Path"));
    let return_path_domain = match return_path.and_then(|rp| {
        rp.rsplit('@')
            .next()
            .map(|d| d.trim_end_matches('>').trim().to_string())
    }) {
        Some(d) if !d.is_empty() => d,
        _ => return false,
    };

    let signing_matches_return_path = dkim
        .domains
        .iter()
        .any(|d| crate::domain_utils::DomainUtils::same_registrable_domain(d, &return_path_domain));
    if !signing_matches_return_path {
        return false;
    }

    // 3. Must be delivered through recognized ESP infrastructure. This is the
    //    anti-abuse gate: a self-signed throwaway domain with a matching
    //    Return-Path still fails here because it is not a recognized ESP.
    esp_validation::is_from_trusted_esp(context)
}

/// Minimum registrable-domain age (days) for a sender to count as "established".
/// ~3 years: long enough that a throwaway/lookalike domain cannot fake it, short enough
/// to cover ordinary small businesses.
pub const ESTABLISHED_DOMAIN_MIN_AGE_DAYS: u32 = 1095;

/// Registrable domain of the From header address, lowercased.
pub fn from_registrable_domain(context: &MailContext) -> Option<String> {
    let from = context.from_header.as_deref()?;
    let addr = from.rsplit('<').next().unwrap_or(from);
    let host = addr
        .rsplit('@')
        .next()?
        .trim_matches(|c: char| c == '>' || c == ' ' || c == '"' || c == ';' || c == ',');
    if !host.contains('.') {
        return None;
    }
    Some(crate::domain_utils::DomainUtils::registrable_domain(host))
}

/// True when every http(s) link target in the body stays on `registrable` (or a subdomain
/// of it). A body with no links trivially qualifies; callers combine this with other signals.
///
/// HTML document identifiers are not link targets and are ignored: DOCTYPE/DTD URLs and
/// XML namespace declarations (`xmlns="http://www.w3.org/..."`) appear in nearly every HTML
/// email and would otherwise make every sender look like it links off-domain.
pub fn links_stay_on_domain(body: &str, registrable: &str) -> bool {
    use regex::Regex;
    let url_re = Regex::new(r#"https?://([^/\s<>"')\]:?#]+)"#).unwrap();
    // Strip DOCTYPE declarations and xmlns attributes before scanning.
    let doctype_re = Regex::new(r"(?is)<!DOCTYPE[^>]*>").unwrap();
    let xmlns_re = Regex::new(r#"(?i)\bxmlns(?::[a-z0-9_-]+)?\s*=\s*["'][^"']*["']"#).unwrap();
    // The body may still be quoted-printable encoded (soft line breaks split hostnames,
    // "=3D" hides attribute syntax). Decode it robustly first; fall back to the raw text.
    let decoded = if body.contains("=\n") || body.contains("=\r\n") || body.contains("=3D") {
        quoted_printable::decode(body.as_bytes(), quoted_printable::ParseMode::Robust)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|_| body.to_string())
    } else {
        body.to_string()
    };
    let cleaned = doctype_re.replace_all(&decoded, " ");
    let cleaned = xmlns_re.replace_all(&cleaned, " ");
    let hosts: Vec<String> = url_re
        .captures_iter(&cleaned)
        .map(|c| c[1].to_lowercase())
        .collect();
    hosts
        .iter()
        .all(|h| crate::domain_utils::DomainUtils::same_registrable_domain(h, registrable))
}

/// Recognize an established, self-contained sender: a long-lived domain that signs its own
/// mail (DKIM pass, aligned with From), carries at most plain PDF attachments, and only links
/// back to itself. Used to stop generic invoice/billing heuristics from flagging real billing mail
/// from a vendor that isn't on any hardcoded allow-list (e.g. a hosting provider's invoice).
///
/// Domain age is the load-bearing signal: aligned DKIM and own-domain links are trivially
/// reproducible on a throwaway domain, but registration age is not. An unknown age (no
/// WHOIS result) NEVER qualifies, so lookup failures fail closed.
pub fn is_established_self_contained_sender(context: &MailContext) -> bool {
    let age = match context.sender_domain_age_days {
        Some(a) => a,
        None => {
            log::debug!("Established-sender check: sender domain age unknown");
            return false;
        }
    };
    if age < ESTABLISHED_DOMAIN_MIN_AGE_DAYS {
        return false;
    }
    let from_domain = match from_registrable_domain(context) {
        Some(d) => d,
        None => return false,
    };
    // Attachments are only tolerated when they are plain PDFs (a real vendor invoice
    // normally ships one). Anything else -- archives, office docs, executables -- is the
    // classic fake-invoice vector and disqualifies the sender.
    if context.attachments.iter().any(|a| {
        a.contains_executables || !a.content_type.to_lowercase().starts_with("application/pdf")
    }) {
        log::debug!(
            "Established-sender check: non-PDF or executable attachment present: {:?}",
            context.attachments
        );
        return false;
    }

    // DKIM must pass with a signing domain in the same organization as From.
    let dkim = match context.dkim_verification.as_ref() {
        Some(d) => d.clone(),
        None => {
            crate::dkim_verification::DkimVerifier::verify(&context.headers, Some(&from_domain))
        }
    };
    if !matches!(
        dkim.auth_status,
        crate::dkim_verification::DkimAuthStatus::Pass
    ) {
        log::debug!(
            "Established-sender check: DKIM status {:?}",
            dkim.auth_status
        );
        return false;
    }
    let dkim_in_org = dkim
        .domains
        .iter()
        .any(|d| crate::domain_utils::DomainUtils::same_registrable_domain(d, &from_domain));
    if !dkim_in_org {
        log::debug!(
            "Established-sender check: DKIM domains {:?} not in org {from_domain}",
            dkim.domains
        );
        return false;
    }

    // Links in the body AND in any text extracted from the PDF must stay on the sender's
    // domain (a PDF that sends you to a different site to "pay" is not self-contained).
    let body_ok = links_stay_on_domain(context.body.as_deref().unwrap_or(""), &from_domain);
    let media_ok = links_stay_on_domain(&context.extracted_media_text, &from_domain);
    log::debug!(
        "Established-sender check for {from_domain}: age={age}d body_links_ok={body_ok} media_links_ok={media_ok}"
    );
    body_ok && media_ok
}

/// Structured tags for inter-feature communication.
/// Features emit tags alongside evidence strings. The trust system and other
/// consumers read tags instead of parsing evidence text, giving compile-time safety.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FeatureTag {
    DkimPassed,
    DkimAligned,
    DkimMisalignedLegitimateEsp,
    TrustedEsp(String),
    LegitimateFinancial,
    BrandImpersonation(String),
    SuspiciousDomain,
}

#[derive(Debug, Clone)]
pub struct FeatureScore {
    pub feature_name: String,
    pub score: i32,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub tags: Vec<FeatureTag>,
}

#[derive(Debug, Clone)]
pub struct FeatureAnalysis {
    pub scores: Vec<FeatureScore>,
    pub total_score: i32,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub trait FeatureExtractor: Send + Sync {
    fn extract(&self, context: &MailContext) -> FeatureScore;
    fn name(&self) -> &str;
}

pub struct FeatureEngine {
    extractors: Vec<Box<dyn FeatureExtractor>>,
}

impl Default for FeatureEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureEngine {
    pub fn new() -> Self {
        Self::from_config_dir("features").unwrap_or_else(|e| {
            log::warn!("Failed to load feature config, using defaults: {}", e);
            Self::default_config()
        })
    }

    pub fn from_config_dir(config_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Try to load feature configurations from TOML files
        let config_path = format!("{}/feature_scoring.toml", config_dir);

        if std::path::Path::new(&config_path).exists() {
            let config = crate::config_loader::ConfigLoader::load_feature_scoring(config_dir)?;
            Ok(Self::from_config(config))
        } else {
            log::warn!(
                "Feature config file not found: {}, using defaults",
                config_path
            );
            Ok(Self::default_config())
        }
    }

    fn from_config(config: crate::config_loader::FeatureScoringConfig) -> Self {
        Self {
            extractors: vec![
                Box::new(link_analyzer::LinkAnalyzer::from_config(
                    &config.feature_scoring.link_analysis,
                )),
                Box::new(sender_alignment::SenderAlignmentAnalyzer::from_config(
                    &config.feature_scoring.sender_alignment,
                )),
                Box::new(context_analyzer::ContextAnalyzer::from_config(
                    &config.feature_scoring.context_analysis,
                )),
                Box::new(invoice_analyzer::InvoiceAnalyzer::from_config(
                    &config.feature_scoring.invoice_analysis,
                )),
                Box::new(domain_reputation::DomainReputationFeature::new()),
                Box::new(brand_impersonation::BrandImpersonationFeature::new()),
                Box::new(financial_validation::FinancialValidationFeature::new()),
                Box::new(esp_validation::EspValidationFeature::new()),
                Box::new(tld_risk::TldRiskFeature::new()),
                Box::new(authentication_analysis::AuthenticationFeature::new()),
                Box::new(domain_business_mismatch::DomainBusinessMismatchAnalyzer::new()),
                Box::new(system_blocklist::SystemBlocklistFeature::new()),
                Box::new(priority_abuse::PriorityAbuseFeature::new()),
                Box::new(unicode_obfuscation::UnicodeObfuscationAnalyzer::new()),
                Box::new(portuguese_language::PortugueseLanguageAnalyzer::new()),
                Box::new(health_spam::HealthSpamAnalyzer::new()),
                Box::new(product_spam::ProductSpamAnalyzer::new()),
                Box::new(server_role_analyzer::ServerRoleAnalyzer::new()),
            ],
        }
    }

    pub fn default_config() -> Self {
        Self {
            extractors: vec![
                Box::new(link_analyzer::LinkAnalyzer::new()),
                Box::new(sender_alignment::SenderAlignmentAnalyzer::new()),
                Box::new(context_analyzer::ContextAnalyzer::new()),
                Box::new(invoice_analyzer::InvoiceAnalyzer::new()),
                Box::new(domain_reputation::DomainReputationFeature::new()),
                Box::new(brand_impersonation::BrandImpersonationFeature::new()),
                Box::new(financial_validation::FinancialValidationFeature::new()),
                Box::new(esp_validation::EspValidationFeature::new()),
                Box::new(tld_risk::TldRiskFeature::new()),
                Box::new(authentication_analysis::AuthenticationFeature::new()),
                Box::new(domain_business_mismatch::DomainBusinessMismatchAnalyzer::new()),
                Box::new(system_blocklist::SystemBlocklistFeature::new()),
                Box::new(priority_abuse::PriorityAbuseFeature::new()),
                Box::new(unicode_obfuscation::UnicodeObfuscationAnalyzer::new()),
                Box::new(portuguese_language::PortugueseLanguageAnalyzer::new()),
                Box::new(health_spam::HealthSpamAnalyzer::new()),
                Box::new(product_spam::ProductSpamAnalyzer::new()),
                Box::new(server_role_analyzer::ServerRoleAnalyzer::new()),
            ],
        }
    }

    pub fn analyze(&self, context: &MailContext) -> FeatureAnalysis {
        let mut scores = Vec::new();
        let mut total_score = 0;

        for extractor in &self.extractors {
            let score = extractor.extract(context);
            total_score += score.score;
            scores.push(score);
        }

        let risk_level = match total_score {
            score if score >= 100 => RiskLevel::Critical,
            score if score >= 50 => RiskLevel::High,
            score if score >= 20 => RiskLevel::Medium,
            _ => RiskLevel::Low,
        };

        FeatureAnalysis {
            scores,
            total_score,
            risk_level,
        }
    }
}
