use chrono;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Module {
    pub name: String,
    pub enabled: bool,
    pub rules: Vec<FilterRule>,
    #[serde(skip)]
    pub hash: String,
}

impl Module {
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let mut module: Module = serde_yml::from_str(&content)?;

        // Calculate hash of the module content
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        module.hash = format!("{:x}", hasher.finish())[..8].to_string();

        Ok(module)
    }
}

pub fn load_modules(module_dir: &str) -> Result<Vec<Module>, Box<dyn std::error::Error>> {
    println!("DEBUG: Attempting to load modules from: {}", module_dir);
    let mut modules = Vec::new();

    // Read all .yaml files from the modules directory
    let dir_path = Path::new(module_dir);
    if !dir_path.exists() {
        return Err(format!("Module directory does not exist: {}", module_dir).into());
    }

    let mut yaml_files = Vec::new();
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(extension) = path.extension() {
                if extension == "yaml" || extension == "yml" {
                    yaml_files.push(path);
                }
            }
        }
    }

    // Sort files for consistent loading order
    yaml_files.sort();

    println!(
        "DEBUG: Found {} YAML files in {}",
        yaml_files.len(),
        module_dir
    );

    for path in &yaml_files {
        let file_name = path.file_name().unwrap().to_string_lossy();
        println!("DEBUG: Checking file: {:?}", path);
        println!("DEBUG: File exists, attempting to load: {}", file_name);
        match Module::load_from_file(path) {
            Ok(module) => {
                println!(
                    "DEBUG: Successfully loaded module: {} (enabled: {})",
                    module.name, module.enabled
                );
                if module.enabled {
                    modules.push(module);
                }
            }
            Err(e) => {
                println!("DEBUG: Failed to load module {}: {}", file_name, e);
                eprintln!("Warning: Failed to load module {}: {}", file_name, e);
            }
        }
    }

    println!("DEBUG: Total modules loaded: {}", modules.len());
    Ok(modules)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub socket_path: String,
    pub rules: Vec<FilterRule>,
    pub default_action: Action,
    pub statistics: Option<StatisticsConfig>,
    pub smtp: Option<SmtpConfig>,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_rule_set_timestamp")]
    pub rule_set_timestamp: String,
    pub module_config_dir: Option<String>,
}

fn default_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn default_rule_set_timestamp() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticsConfig {
    pub enabled: bool,
    pub database_path: String,
    pub flush_interval_seconds: Option<u64>, // How often to flush stats to disk (default: 60)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub server: String,               // SMTP server hostname
    pub port: Option<u16>,            // SMTP port (default: 587 for STARTTLS, 465 for SSL)
    pub username: Option<String>,     // SMTP username (optional for anonymous)
    pub password: Option<String>,     // SMTP password (optional for anonymous)
    pub from_email: String,           // From email address for abuse reports
    pub from_name: Option<String>,    // From name for abuse reports (default: "FOFF Milter")
    pub use_tls: Option<bool>,        // Use STARTTLS (default: true)
    pub timeout_seconds: Option<u64>, // Connection timeout (default: 30)
}

impl Default for StatisticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            database_path: "/var/lib/foff-milter/stats.db".to_string(),
            flush_interval_seconds: Some(60),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterRule {
    pub name: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub criteria: Criteria,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Criteria {
    MailerPattern {
        pattern: String,
    },
    SenderPattern {
        pattern: String,
    },
    RecipientPattern {
        pattern: String,
    },
    SubjectPattern {
        pattern: String,
    },
    BodyPattern {
        pattern: String,
    },
    MediaTextPattern {
        pattern: String,
    },
    CombinedTextPattern {
        pattern: String,
    },
    HeaderPattern {
        header: String,
        pattern: String,
    },
    SubjectContainsLanguage {
        language: String,
    },
    HeaderContainsLanguage {
        header: String,
        language: String,
    },
    UnsubscribeLinkValidation {
        timeout_seconds: Option<u64>,
        check_dns: Option<bool>,
        check_http: Option<bool>,
    },
    UnsubscribeLinkPattern {
        pattern: String,
    },
    /// Detect unsubscribe links that use IP addresses instead of domain names
    /// This is a strong spam indicator as legitimate businesses use proper domains
    UnsubscribeLinkIPAddress {
        // Whether to check both IPv4 and IPv6 addresses (default: true)
        check_ipv4: Option<bool>,
        // Whether to check IPv6 addresses (default: true)
        check_ipv6: Option<bool>,
        // Whether to allow private/local IP addresses (default: false)
        allow_private_ips: Option<bool>,
    },
    UnsubscribeMailtoOnly {
        // Detects emails where ALL unsubscribe links are mailto: links
        // This is suspicious as legitimate bulk email services use HTTP links
        allow_mixed: Option<bool>, // If true, only flag if ALL links are mailto (default: false)
    },
    PhishingSenderSpoofing {
        // Detects when From header display name claims to be from a different domain than the actual sender
        trusted_domains: Vec<String>,
    },
    PhishingSuspiciousLinks {
        // Detects suspicious link patterns commonly used in phishing
        check_url_shorteners: Option<bool>,
        check_suspicious_tlds: Option<bool>,
        check_ip_addresses: Option<bool>,
        suspicious_patterns: Option<Vec<String>>,
        allow_sender_domain: Option<bool>,
        allow_email_infrastructure: Option<bool>,
        email_infrastructure_domains: Option<Vec<String>>,
    },
    PhishingDomainMismatch {
        // Detects when Reply-To domain differs significantly from sender domain
        allow_subdomains: Option<bool>,
    },
    PhishingLinkRedirection {
        // Follows redirect chains to detect malicious final destinations
        max_redirects: Option<u32>,
        timeout_seconds: Option<u64>,
        suspicious_redirect_patterns: Option<Vec<String>>,
        check_final_destination: Option<bool>,
    },
    ImageOnlyEmail {
        // Detects emails that contain only images or image links with minimal text
        max_text_length: Option<usize>,
        ignore_whitespace: Option<bool>,
        check_attachments: Option<bool>,
    },
    PhishingFreeEmailReplyTo {
        // Detects when Reply-To is from a free email service but From is from a different domain
        free_email_domains: Option<Vec<String>>,
        allow_same_domain: Option<bool>,
    },
    ReplyToValidation {
        // Validates that the Reply-To email address domain resolves via DNS
        timeout_seconds: Option<u64>,
        check_mx_record: Option<bool>,
    },
    DomainAge {
        // Checks if domains are younger than specified threshold
        max_age_days: u32,
        check_sender: Option<bool>, // Check sender domain (default: true)
        check_reply_to: Option<bool>, // Check reply-to domain (default: false)
        check_from_header: Option<bool>, // Check from header domain (default: false)
        timeout_seconds: Option<u64>, // WHOIS lookup timeout (default: 10)
        use_mock_data: Option<bool>, // Use mock data for testing (default: false)
    },
    /// Detect emails with invalid unsubscribe header combinations
    /// This catches emails that have List-Unsubscribe-Post but no List-Unsubscribe header
    /// which is an RFC violation and common spam pattern
    InvalidUnsubscribeHeaders,
    /// Detect emails that consist primarily of attachments with minimal text content
    /// Useful for catching malware delivery and phishing attempts via PDF/document attachments
    AttachmentOnlyEmail {
        // Maximum allowed text content length (default: 100 characters)
        max_text_length: Option<usize>,
        // Whether to ignore whitespace when counting text (default: true)
        ignore_whitespace: Option<bool>,
        // Specific attachment types to flag (default: ["pdf", "doc", "docx", "xls", "xlsx"])
        suspicious_types: Option<Vec<String>>,
        // Minimum attachment size to consider suspicious (default: 10KB)
        min_attachment_size: Option<usize>,
        // Whether to check Content-Disposition headers for attachment indicators
        check_disposition: Option<bool>,
    },
    /// Detect emails with no meaningful content (empty body, minimal text)
    /// Useful for catching reconnaissance emails, address validation attempts, and placeholder emails
    EmptyContentEmail {
        // Maximum allowed text content length (default: 10 characters)
        max_text_length: Option<usize>,
        // Whether to ignore whitespace when counting text (default: true)
        ignore_whitespace: Option<bool>,
        // Whether to ignore common email signatures and footers (default: true)
        ignore_signatures: Option<bool>,
        // Whether to require both empty subject AND body (default: false - either is sufficient)
        require_empty_subject: Option<bool>,
        // Minimum subject length to not be considered empty (default: 3 characters)
        min_subject_length: Option<usize>,
        // Whether to ignore HTML tags when counting content (default: true)
        ignore_html_tags: Option<bool>,
    },
    /// Detect abuse of legitimate email services for phishing and brand impersonation
    /// This catches when attackers use services like SendGrid, Mailchimp, etc. to send
    /// phishing emails that impersonate major brands with mismatched reply-to addresses
    EmailServiceAbuse {
        // Legitimate email service domains/patterns to check (default: common services)
        legitimate_services: Option<Vec<String>>,
        // Brand keywords that indicate impersonation (default: major brands)
        brand_keywords: Option<Vec<String>>,
        // Free email domains for reply-to mismatch detection (default: common free services)
        free_email_domains: Option<Vec<String>>,
        // Whether to check for reply-to domain mismatch (default: true)
        check_reply_to_mismatch: Option<bool>,
        // Whether to check for brand impersonation in From header (default: true)
        check_brand_impersonation: Option<bool>,
        // Whether to check for suspicious subject patterns (default: true)
        check_suspicious_subjects: Option<bool>,
    },
    /// Detect abuse of Google Groups mailing lists for phishing campaigns
    /// This catches when attackers use Google Groups infrastructure to send
    /// phishing emails with reward/prize scams from suspicious domains
    GoogleGroupsAbuse {
        // Suspicious domain patterns to check (default: common spam TLDs and patterns)
        suspicious_domains: Option<Vec<String>>,
        // Reward/prize keywords that indicate scam content (default: common scam terms)
        reward_keywords: Option<Vec<String>>,
        // Suspicious sender name patterns (default: generic/urgent patterns)
        suspicious_sender_names: Option<Vec<String>>,
        // Whether to check domain reputation (default: true)
        check_domain_reputation: Option<bool>,
        // Whether to check for reward/prize subjects (default: true)
        check_reward_subjects: Option<bool>,
        // Whether to check for suspicious sender names (default: true)
        check_suspicious_senders: Option<bool>,
        // Minimum number of abuse indicators required for a match (default: 2)
        min_indicators: Option<u32>,
    },
    /// Detect sender spoofing extortion attempts where attackers pretend to be the recipient
    /// This catches extortion/sextortion emails that spoof the sender to appear self-sent
    SenderSpoofingExtortion {
        // Extortion keywords that indicate blackmail/sextortion content (default: common extortion terms)
        extortion_keywords: Option<Vec<String>>,
        // Whether to check if sender and recipient addresses match (default: true)
        check_sender_recipient_match: Option<bool>,
        // Whether to check for external/suspicious source IPs (default: true)
        check_external_source: Option<bool>,
        // Whether to check for missing DKIM authentication (default: true)
        check_missing_authentication: Option<bool>,
        // Whether to require extortion content in subject/body (default: true)
        require_extortion_content: Option<bool>,
        // Minimum number of indicators required for a match (default: 2)
        min_indicators: Option<u32>,
    },
    /// Detect abuse of DocuSign infrastructure for phishing campaigns
    /// This catches sophisticated phishing attacks that abuse legitimate DocuSign services
    DocuSignAbuse {
        // Whether to check for reply-to domain mismatch (default: true)
        check_reply_to_mismatch: Option<bool>,
        // Whether to check for panic/urgent subjects (default: true)
        check_panic_subjects: Option<bool>,
        // Whether to check for suspicious base64 encoding in From header (default: true)
        check_suspicious_encoding: Option<bool>,
        // Minimum number of indicators required for detection (default: 2)
        min_indicators: Option<u32>,
    },
    /// Direct DKIM signature analysis without relying on Authentication-Results
    /// Analyzes DKIM signatures and domain relationships for authentication failures
    DkimAnalysis {
        // Whether to require DKIM signature presence (default: true)
        require_signature: Option<bool>,
        // Whether to check for domain mismatch between signature and sender (default: true)
        check_domain_mismatch: Option<bool>,
        // Whether to detect multi-domain DKIM spoofing (default: false)
        detect_spoofing: Option<bool>,
        // List of brand domains to check for spoofing
        brand_domains: Option<Vec<String>>,
        // List of suspicious domains that indicate potential spoofing
        suspicious_domains: Option<Vec<String>>,
    },
    /// Detect language/geography mismatches (e.g., Japanese text from Chinese domains)
    LanguageGeographyMismatch {
        // Domain pattern to match (e.g., "(?i).*\\.cn$")
        domain_pattern: String,
        // Content pattern to detect language (e.g., Japanese Unicode ranges)
        content_pattern: String,
        // Description of the mismatch being detected
        description: String,
    },
    /// Detect suspicious mixing of different writing systems for obfuscation
    MixedScriptDetection {
        // List of suspicious script combinations to detect
        suspicious_combinations: Vec<String>,
        // Threshold for number of different scripts before flagging
        threshold: u32,
    },
    BrandImpersonation {
        // Detects brand impersonation using centralized brand configuration
        brand_name: String, // Brand identifier (e.g., "docusign", "paypal")
        subject_patterns: Option<Vec<String>>, // Brand-specific subject patterns
        sender_patterns: Option<Vec<String>>, // Brand-specific sender patterns
        body_patterns: Option<Vec<String>>, // Brand-specific body patterns
        legitimate_domains: Vec<String>, // Official brand domains to exclude
        require_auth_failure: Option<bool>, // Require authentication failure (default: false)
        suspicious_tlds: Option<Vec<String>>, // Specific suspicious TLDs for this brand
    },
    EmailInfrastructure {
        // Centralized email infrastructure detection and classification
        infrastructure_type: String, // Type: "free_email", "educational", "compromised", "business"
        domains: Option<Vec<String>>, // Specific domains to check
        tld_patterns: Option<Vec<String>>, // TLD patterns (e.g., ".edu", ".onmicrosoft.com")
        check_sender: Option<bool>,  // Check sender domain (default: true)
        check_reply_to: Option<bool>, // Check reply-to domain (default: false)
        require_auth_failure: Option<bool>, // Require authentication failure (default: false)
        exclude_legitimate: Option<bool>, // Exclude legitimate business use (default: true)
    },
    FreeEmailProvider {
        // Detects emails from free email providers (gmail, outlook, etc.)
        // Uses centralized domain classification from TOML config
        check_sender: Option<bool>, // Check sender domain (default: true)
        check_reply_to: Option<bool>, // Check reply-to domain (default: false)
    },
    /// Detect attachments containing executable files or malicious content
    /// Analyzes archive contents (RAR, ZIP) for dangerous file types
    MaliciousAttachment {
        // File extensions to consider dangerous (default: exe, scr, bat, cmd, com, pif, vbs, js, jar, msi)
        dangerous_extensions: Option<Vec<String>>,
        // Archive types to analyze (default: rar, zip)
        archive_types: Option<Vec<String>>,
        // Whether to use pattern matching fallback if archive parsing fails (default: true)
        use_pattern_fallback: Option<bool>,
    },
    And {
        criteria: Vec<Criteria>,
    },
    Or {
        criteria: Vec<Criteria>,
    },
    Not {
        criteria: Box<Criteria>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Action {
    Reject {
        message: String,
    },
    TagAsSpam {
        header_name: String,
        header_value: String,
    },
    /// Report abuse to the email service provider and optionally take additional action
    ReportAbuse {
        // Email service provider to report to (e.g., "sendgrid", "mailchimp", "constantcontact")
        service_provider: String,
        // Additional action to take after reporting (optional)
        additional_action: Option<Box<Action>>,
        // Whether to include email headers in the abuse report (default: true)
        include_headers: Option<bool>,
        // Whether to include email body in the abuse report (default: false for privacy)
        include_body: Option<bool>,
        // Custom abuse report message (optional)
        report_message: Option<String>,
    },
    /// Automatically unsubscribe from Google Groups and optionally take additional action
    UnsubscribeGoogleGroup {
        // Additional action to take after unsubscribing (optional)
        additional_action: Option<Box<Action>>,
        // Custom reason for unsubscribing (optional)
        reason: Option<String>,
    },
    Accept,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            socket_path: "/var/run/foff-milter.sock".to_string(),
            rules: vec![
                FilterRule {
                    name: "Block suspicious Chinese services".to_string(),
                    enabled: true,
                    criteria: Criteria::MailerPattern {
                        pattern: r"service\..*\.cn".to_string(),
                    },
                    action: Some(Action::Reject {
                        message: "Mail from suspicious service rejected".to_string(),
                    }),
                    score: None,
                    description: None,
                },
                FilterRule {
                    name: "Tag potential spam".to_string(),
                    enabled: true,
                    criteria: Criteria::MailerPattern {
                        pattern: r".*spam.*".to_string(),
                    },
                    action: Some(Action::TagAsSpam {
                        header_name: "X-Spam-Flag".to_string(),
                        header_value: "YES".to_string(),
                    }),
                    score: None,
                    description: None,
                },
            ],
            default_action: Action::Accept,
            statistics: Some(StatisticsConfig::default()),
            smtp: None,
            version: default_version(),
            rule_set_timestamp: default_rule_set_timestamp(),
            module_config_dir: None,
        }
    }
}
