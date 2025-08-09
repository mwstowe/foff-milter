use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub socket_path: String,
    pub rules: Vec<FilterRule>,
    pub default_action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    pub name: String,
    pub criteria: Criteria,
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
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
    And {
        criteria: Vec<Criteria>,
    },
    Or {
        criteria: Vec<Criteria>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    Reject {
        message: String,
    },
    TagAsSpam {
        header_name: String,
        header_value: String,
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
                    criteria: Criteria::MailerPattern {
                        pattern: r"service\..*\.cn".to_string(),
                    },
                    action: Action::Reject {
                        message: "Mail from suspicious service rejected".to_string(),
                    },
                },
                FilterRule {
                    name: "Tag potential spam".to_string(),
                    criteria: Criteria::MailerPattern {
                        pattern: r".*spam.*".to_string(),
                    },
                    action: Action::TagAsSpam {
                        header_name: "X-Spam-Flag".to_string(),
                        header_value: "YES".to_string(),
                    },
                },
            ],
            default_action: Action::Accept,
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn to_file(&self, path: &str) -> anyhow::Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
