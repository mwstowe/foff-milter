use anyhow::{anyhow, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    pub domain: String,
    pub creation_date: Option<SystemTime>,
    pub age_days: Option<u32>,
    pub cached_at: SystemTime,
}

/// How long a successful lookup is reused.
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long a failed lookup is reused. Without this, a domain whose registry has no
/// usable WHOIS costs a full timeout on every message from it.
const FAILURE_TTL: Duration = Duration::from_secs(60 * 60);
/// Most domains kept in the cache; a long-running milter sees many senders.
const CACHE_CAPACITY: usize = 10_000;

#[derive(Debug, Clone)]
enum CacheEntry {
    Known(DomainInfo),
    Failed { error: String, at: SystemTime },
}

impl CacheEntry {
    fn stored_at(&self) -> SystemTime {
        match self {
            CacheEntry::Known(info) => info.cached_at,
            CacheEntry::Failed { at, .. } => *at,
        }
    }

    fn is_fresh(&self, now: SystemTime) -> bool {
        let ttl = match self {
            CacheEntry::Known(_) => CACHE_TTL,
            CacheEntry::Failed { .. } => FAILURE_TTL,
        };
        now.duration_since(self.stored_at())
            .map(|age| age < ttl)
            .unwrap_or(true)
    }
}

/// Looks up domain registration dates via WHOIS.
///
/// Clones share one cache, so create a single checker and clone it (or use
/// [`with_timeout`](Self::with_timeout)) rather than creating one per lookup.
#[derive(Debug, Clone)]
pub struct DomainAgeChecker {
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    timeout: Duration,
    use_mock: bool,
}

/// The registry WHOIS server named by a `refer:` line (IANA referral format).
fn whois_referral(response: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        let value = value.trim();
        (key.trim().eq_ignore_ascii_case("refer") && !value.is_empty()).then(|| value.to_string())
    })
}

/// Whether a WHOIS response comes from whois.iana.org, which only knows about TLDs.
fn is_iana_response(response: &str) -> bool {
    response.contains("% IANA WHOIS server")
}

impl DomainAgeChecker {
    pub fn new(timeout_seconds: u64, use_mock: bool) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            timeout: Duration::from_secs(timeout_seconds),
            use_mock,
        }
    }

    /// A checker with a different query timeout that shares this checker's cache.
    pub fn with_timeout(&self, timeout_seconds: u64) -> Self {
        Self {
            cache: Arc::clone(&self.cache),
            timeout: Duration::from_secs(timeout_seconds),
            use_mock: self.use_mock,
        }
    }

    /// Extract domain from email address
    pub fn extract_domain(email: &str) -> Option<String> {
        if let Some(at_pos) = email.rfind('@') {
            // Check that there's something before the @
            if at_pos == 0 {
                return None;
            }
            let domain_part = &email[at_pos + 1..];

            // Clean up the domain part - remove common SMTP artifacts
            let domain = domain_part
                .split_whitespace() // Remove whitespace
                .next()? // Take first part
                .split('>') // Remove > characters
                .next()?
                .split(',') // Remove comma-separated parameters
                .next()?
                .split(';') // Remove semicolon-separated parameters
                .next()?
                .trim(); // Final cleanup

            // Basic domain validation
            if domain.contains('.') && !domain.is_empty() && domain.len() < 255 {
                // Additional validation - domain should only contain valid characters
                if domain
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                {
                    return Some(domain.to_lowercase());
                }
            }
        }
        None
    }

    /// Extract root domain for WHOIS queries (removes subdomains)
    /// e.g., "email.nationalgeographic.com" -> "nationalgeographic.com"
    pub fn extract_root_domain(&self, domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();

        // Handle special cases and common TLD patterns
        if parts.len() >= 2 {
            // For most domains, take the last two parts (domain.tld)
            let root = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);

            // Handle common two-part TLDs like .co.uk, .com.au, etc.
            if parts.len() >= 3 {
                let potential_tld =
                    format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
                let common_two_part_tlds = [
                    "co.uk", "com.au", "co.jp", "co.kr", "com.br", "co.za", "com.mx", "co.in",
                    "com.sg", "co.nz", "com.ar", "co.il", "org.uk", "net.au", "gov.uk", "ac.uk",
                    "edu.au",
                ];

                if common_two_part_tlds.contains(&potential_tld.as_str()) {
                    return format!(
                        "{}.{}.{}",
                        parts[parts.len() - 3],
                        parts[parts.len() - 2],
                        parts[parts.len() - 1]
                    );
                }
            }

            root
        } else {
            // If less than 2 parts, return as-is
            domain.to_string()
        }
    }

    /// Check if domain is younger than max_age_days
    pub async fn is_domain_young(&self, domain: &str, max_age_days: u32) -> Result<bool> {
        // Extract root domain for WHOIS query
        let root_domain = self.extract_root_domain(domain);
        log::debug!("Checking domain age for {domain} (root: {root_domain})");

        // Basic domain validation to prevent invalid WHOIS queries
        if root_domain.is_empty()
            || root_domain.contains(',')
            || root_domain.contains(';')
            || root_domain.contains('>')
            || root_domain.contains(' ')
            || !root_domain.contains('.')
        {
            log::warn!("Invalid domain format: {root_domain} (from: {domain})");
            return Ok(false); // Invalid domains are not considered "young"
        }

        let domain_info = self.get_domain_info(&root_domain).await?;

        match domain_info.age_days {
            Some(age) => {
                log::debug!("Domain {domain} is {age} days old (threshold: {max_age_days})");
                Ok(age <= max_age_days)
            }
            None => {
                log::warn!("Could not determine age for domain: {domain} (root: {root_domain})");
                Ok(false) // If we can't determine age, don't flag as young
            }
        }
    }

    /// Get domain information (with caching). Failed lookups are cached too, for a
    /// shorter time, and keep returning the error while cached.
    pub async fn get_domain_info(&self, domain: &str) -> Result<DomainInfo> {
        let domain = domain.to_lowercase();

        // Check cache first
        {
            let cache = self.cache.read().await;
            match cache.get(&domain) {
                Some(entry) if entry.is_fresh(SystemTime::now()) => {
                    log::debug!("Using cached domain info for: {domain}");
                    return match entry {
                        CacheEntry::Known(info) => Ok(info.clone()),
                        CacheEntry::Failed { error, .. } => {
                            Err(anyhow!("{error} (cached failure)"))
                        }
                    };
                }
                _ => {}
            }
        }

        // Fetch fresh data
        let result = if self.use_mock {
            self.get_mock_domain_info(&domain).await
        } else {
            self.fetch_domain_info(&domain).await
        };

        let entry = match &result {
            Ok(info) => CacheEntry::Known(info.clone()),
            Err(e) => CacheEntry::Failed {
                error: e.to_string(),
                at: SystemTime::now(),
            },
        };
        let mut cache = self.cache.write().await;
        if cache.len() >= CACHE_CAPACITY && !cache.contains_key(&domain) {
            Self::make_room(&mut cache);
        }
        cache.insert(domain, entry);

        result
    }

    /// Drop expired entries, and if the cache is still full, the oldest tenth.
    fn make_room(cache: &mut HashMap<String, CacheEntry>) {
        let now = SystemTime::now();
        cache.retain(|_, entry| entry.is_fresh(now));
        if cache.len() < CACHE_CAPACITY {
            return;
        }
        let mut by_age: Vec<(SystemTime, String)> = cache
            .iter()
            .map(|(domain, entry)| (entry.stored_at(), domain.clone()))
            .collect();
        by_age.sort();
        for (_, domain) in by_age.into_iter().take(CACHE_CAPACITY / 10) {
            cache.remove(&domain);
        }
    }

    /// Fetch domain information from WHOIS servers
    async fn fetch_domain_info(&self, domain: &str) -> Result<DomainInfo> {
        log::debug!("Fetching WHOIS data for domain: {domain}");

        // First, determine the appropriate WHOIS server for this domain
        let whois_server = self.get_whois_server(domain).await?;
        log::debug!("Using WHOIS server: {whois_server} for domain: {domain}");

        // Query the WHOIS server directly
        match self
            .query_whois_following_referral(&whois_server, domain)
            .await
        {
            Ok(whois_text) => {
                log::debug!("Got WHOIS response ({} chars)", whois_text.len());
                self.parse_text_whois(&whois_text, domain)
            }
            Err(e) => {
                log::debug!("WHOIS query failed: {e}");
                // Try fallback servers
                self.try_fallback_whois_servers(domain).await
            }
        }
    }

    /// Determine the appropriate WHOIS server for a domain
    async fn get_whois_server(&self, domain: &str) -> Result<String> {
        // Extract TLD from domain
        let tld = domain.split('.').next_back().unwrap_or(domain);

        // Common WHOIS servers by TLD
        let whois_servers = std::collections::HashMap::from([
            ("com", "whois.verisign-grs.com"),
            ("net", "whois.verisign-grs.com"),
            ("org", "whois.pir.org"),
            ("info", "whois.afilias.net"),
            ("biz", "whois.neulevel.biz"),
            ("us", "whois.nic.us"),
            ("uk", "whois.nic.uk"),
            ("de", "whois.denic.de"),
            ("fr", "whois.afnic.fr"),
            ("it", "whois.nic.it"),
            ("nl", "whois.domain-registry.nl"),
            ("au", "whois.auda.org.au"),
            ("ca", "whois.cira.ca"),
            ("jp", "whois.jprs.jp"),
            ("cn", "whois.cnnic.cn"),
            ("ru", "whois.tcinet.ru"),
            ("br", "whois.registro.br"),
            ("mx", "whois.mx"),
            ("tk", "whois.dot.tk"),
            ("ml", "whois.dot.ml"),
            ("ga", "whois.dot.ga"),
            ("cf", "whois.dot.cf"),
        ]);

        if let Some(&server) = whois_servers.get(tld) {
            Ok(server.to_string())
        } else {
            // Default to IANA WHOIS for unknown TLDs
            Ok("whois.iana.org".to_string())
        }
    }

    /// Query a WHOIS server directly using TCP port 43
    async fn query_whois_server(&self, server: &str, domain: &str) -> Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        log::debug!("Connecting to WHOIS server: {server}:43");

        // Connect to WHOIS server on port 43
        let mut stream =
            timeout(self.timeout, TcpStream::connect(format!("{server}:43"))).await??;

        // Send domain query
        let query = format!("{domain}\r\n");
        stream.write_all(query.as_bytes()).await?;

        // Read response
        let mut response = String::new();
        timeout(self.timeout, stream.read_to_string(&mut response)).await??;

        if response.is_empty() {
            return Err(anyhow!("Empty WHOIS response"));
        }

        Ok(response)
    }

    /// Query `server`, and if it only refers to the registry's WHOIS server (as
    /// whois.iana.org does for every TLD), query that server instead. IANA's answer
    /// describes the TLD itself, including the TLD's creation date, so it must never
    /// be parsed as the domain's record.
    async fn query_whois_following_referral(&self, server: &str, domain: &str) -> Result<String> {
        let response = self.query_whois_server(server, domain).await?;
        match whois_referral(&response) {
            Some(referred) if !referred.eq_ignore_ascii_case(server) => {
                log::debug!("WHOIS {server} refers {domain} to {referred}");
                self.query_whois_server(&referred, domain).await
            }
            _ if is_iana_response(&response) => {
                Err(anyhow!("IANA has no registry WHOIS server for {domain}"))
            }
            _ => Ok(response),
        }
    }

    /// Try fallback WHOIS servers if primary fails
    async fn try_fallback_whois_servers(&self, domain: &str) -> Result<DomainInfo> {
        let fallback_servers = vec!["whois.iana.org", "whois.internic.net"];

        for server in fallback_servers {
            log::debug!("Trying fallback WHOIS server: {server}");
            match self.query_whois_following_referral(server, domain).await {
                Ok(whois_text) => {
                    if let Ok(info) = self.parse_text_whois(&whois_text, domain) {
                        return Ok(info);
                    }
                }
                Err(e) => {
                    log::debug!("Fallback server {server} failed: {e}");
                    continue;
                }
            }
        }

        // If all WHOIS servers fail, fall back to DNS
        log::debug!("All WHOIS servers failed, using DNS fallback");
        self.fallback_domain_check(domain).await
    }

    /// Parse text WHOIS response
    fn parse_text_whois(&self, text: &str, domain: &str) -> Result<DomainInfo> {
        log::debug!(
            "Parsing WHOIS text ({} chars) for domain: {}",
            text.len(),
            domain
        );

        // A TLD record from IANA carries the TLD's dates, not the domain's
        if is_iana_response(text) {
            return Err(anyhow!("WHOIS response for {domain} is an IANA TLD record"));
        }

        // Common patterns for creation date in WHOIS text
        let patterns = vec![
            // Standard formats
            r"(?i)creation\s*date[:\s]+([^\r\n]+)",
            r"(?i)created[:\s]+([^\r\n]+)",
            r"(?i)registered[:\s]+([^\r\n]+)",
            r"(?i)domain\s*created[:\s]+([^\r\n]+)",
            r"(?i)registration\s*date[:\s]+([^\r\n]+)",
            r"(?i)created\s*on[:\s]+([^\r\n]+)",
            r"(?i)registered\s*on[:\s]+([^\r\n]+)",
            // Registry-specific formats
            r"(?i)domain_date_created[:\s]+([^\r\n]+)",
            r"(?i)create_date[:\s]+([^\r\n]+)",
            r"(?i)created_date[:\s]+([^\r\n]+)",
            r"(?i)registration_time[:\s]+([^\r\n]+)",
            // International formats
            r"(?i)fecha\s*de\s*creaci[oó]n[:\s]+([^\r\n]+)", // Spanish
            r"(?i)date\s*de\s*cr[eé]ation[:\s]+([^\r\n]+)",  // French
            r"(?i)erstellt\s*am[:\s]+([^\r\n]+)",            // German
        ];

        for pattern in patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if let Some(captures) = regex.captures(text) {
                    if let Some(date_match) = captures.get(1) {
                        let date_str = date_match.as_str().trim();
                        log::debug!("Found potential creation date: '{date_str}'");

                        if let Ok(creation_date) = self.parse_date_string(date_str) {
                            let age_days = self.calculate_age_days(creation_date);
                            log::info!(
                                "Successfully parsed creation date for {domain}: {date_str} ({age_days} days old)"
                            );
                            return Ok(DomainInfo {
                                domain: domain.to_string(),
                                creation_date: Some(creation_date),
                                age_days: Some(age_days),
                                cached_at: SystemTime::now(),
                            });
                        } else {
                            log::debug!("Could not parse date format: '{date_str}'");
                        }
                    }
                }
            }
        }

        // If we can't find a creation date, log some of the WHOIS response for debugging
        let preview = if text.len() > 500 {
            // Use char_indices to avoid UTF-8 boundary issues
            let truncate_pos = text
                .char_indices()
                .nth(500)
                .map(|(i, _)| i)
                .unwrap_or(text.len());
            format!("{}...", &text[..truncate_pos])
        } else {
            text.to_string()
        };
        log::debug!("Could not find creation date in WHOIS response. Preview: {preview}");

        Err(anyhow!("Could not parse creation date from WHOIS text"))
    }

    /// Fallback method using DNS to estimate domain age
    async fn fallback_domain_check(&self, domain: &str) -> Result<DomainInfo> {
        log::debug!("Using DNS fallback for domain: {domain}");

        use hickory_resolver::Resolver;

        let resolver = Resolver::builder_tokio().and_then(|b| b.build())?;

        match resolver.lookup_ip(domain).await {
            Ok(_) => {
                log::debug!("Domain {domain} resolves, but age unknown");
                // Domain resolves, but we can't determine age
                Ok(DomainInfo {
                    domain: domain.to_string(),
                    creation_date: None,
                    age_days: None,
                    cached_at: SystemTime::now(),
                })
            }
            Err(e) => Err(anyhow!("Domain does not resolve: {}", e)),
        }
    }

    /// Get mock domain information for testing
    async fn get_mock_domain_info(&self, domain: &str) -> Result<DomainInfo> {
        log::debug!("Using mock data for domain: {domain}");

        // Mock data for testing - you can customize this
        let mock_data = HashMap::from([
            ("psybook.info", 90),      // 90 days old (young)
            ("example.com", 8000),     // Very old domain
            ("google.com", 9000),      // Very old domain
            ("suspicious.tk", 30),     // 30 days old (very young)
            ("newdomain.info", 45),    // 45 days old (young)
            ("established.org", 3650), // 10 years old
        ]);

        let age_days = mock_data.get(domain).copied().unwrap_or(365); // Default to 1 year

        let creation_date = SystemTime::now()
            .checked_sub(Duration::from_secs(age_days as u64 * 24 * 60 * 60))
            .unwrap_or(SystemTime::now());

        Ok(DomainInfo {
            domain: domain.to_string(),
            creation_date: Some(creation_date),
            age_days: Some(age_days),
            cached_at: SystemTime::now(),
        })
    }

    /// Parse various date string formats
    fn parse_date_string(&self, date_str: &str) -> Result<SystemTime> {
        let date_str = date_str.trim();

        // Common date formats in WHOIS responses
        let formats = vec![
            "%Y-%m-%d",           // 2024-10-10
            "%Y-%m-%dT%H:%M:%SZ", // 2024-10-10T12:00:00Z
            "%Y-%m-%d %H:%M:%S",  // 2024-10-10 12:00:00
            "%d-%m-%Y",           // 10-10-2024
            "%m/%d/%Y",           // 10/10/2024
            "%d.%m.%Y",           // 10.10.2024
        ];

        // Try parsing with chrono if available, otherwise use a simple approach
        for format in formats {
            if let Ok(parsed) = self.try_parse_date_simple(date_str, format) {
                return Ok(parsed);
            }
        }

        Err(anyhow!("Could not parse date: {}", date_str))
    }

    /// Simple date parsing without external dependencies
    fn try_parse_date_simple(&self, date_str: &str, _format: &str) -> Result<SystemTime> {
        // Simple regex-based parsing for common formats
        let iso_regex = Regex::new(r"(\d{4})-(\d{2})-(\d{2})").unwrap();

        if let Some(captures) = iso_regex.captures(date_str) {
            let year: u32 = captures[1].parse()?;
            let month: u32 = captures[2].parse()?;
            let day: u32 = captures[3].parse()?;

            // Simple conversion to timestamp (approximate)
            let days_since_epoch = self.days_since_epoch(year, month, day)?;
            let timestamp = Duration::from_secs(days_since_epoch * 24 * 60 * 60);

            return Ok(UNIX_EPOCH + timestamp);
        }

        Err(anyhow!("Date format not supported"))
    }

    /// Calculate days since Unix epoch (approximate)
    fn days_since_epoch(&self, year: u32, month: u32, day: u32) -> Result<u64> {
        if year < 1970 || month == 0 || month > 12 || day == 0 || day > 31 {
            return Err(anyhow!("Invalid date"));
        }

        // Approximate calculation (good enough for domain age checking)
        let years_since_1970 = year - 1970;
        let mut days = years_since_1970 as u64 * 365;

        // Add leap days (approximate)
        days += years_since_1970 as u64 / 4;

        // Add days for months (approximate)
        let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        for m in 1..month {
            days += days_in_month[(m - 1) as usize] as u64;
        }

        days += day as u64 - 1;

        Ok(days)
    }

    /// Calculate age in days from creation date
    fn calculate_age_days(&self, creation_date: SystemTime) -> u32 {
        let age_secs = SystemTime::now()
            .duration_since(creation_date)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        (age_secs / (24 * 60 * 60)) as u32
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_iana_referral_is_followed_not_parsed() {
        // whois.iana.org's answer for a domain on a TLD without a known server
        let iana = "% IANA WHOIS server\n% for more information on IANA, visit http://www.iana.org\n\nrefer:        whois.nic.buzz\n\ndomain:       BUZZ\ncreated:      2013-12-12\n";
        assert_eq!(whois_referral(iana).as_deref(), Some("whois.nic.buzz"));
        assert!(is_iana_response(iana));

        let checker = DomainAgeChecker::new(5, false);
        assert!(checker.parse_text_whois(iana, "schwab-6.buzz").is_err());

        let registry = "Domain Name: schwab-6.buzz\nCreation Date: 2026-02-02T04:13:35Z\n";
        assert_eq!(whois_referral(registry), None);
        assert!(!is_iana_response(registry));
        assert!(checker.parse_text_whois(registry, "schwab-6.buzz").is_ok());
    }

    use super::*;

    #[test]
    fn test_extract_domain() {
        // Normal cases
        assert_eq!(
            DomainAgeChecker::extract_domain("user@example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            DomainAgeChecker::extract_domain("test@sub.domain.org"),
            Some("sub.domain.org".to_string())
        );

        // Malformed cases that should be cleaned up
        assert_eq!(
            DomainAgeChecker::extract_domain("user@sendgrid.net>,body=8bitmime"),
            Some("sendgrid.net".to_string())
        );
        assert_eq!(
            DomainAgeChecker::extract_domain("user@example.com>"),
            Some("example.com".to_string())
        );
        assert_eq!(
            DomainAgeChecker::extract_domain("user@domain.com,param=value"),
            Some("domain.com".to_string())
        );
        assert_eq!(
            DomainAgeChecker::extract_domain("user@domain.com;param=value"),
            Some("domain.com".to_string())
        );
        assert_eq!(
            DomainAgeChecker::extract_domain("user@domain.com extra stuff"),
            Some("domain.com".to_string())
        );

        // Invalid cases
        assert_eq!(DomainAgeChecker::extract_domain("invalid"), None);
        assert_eq!(DomainAgeChecker::extract_domain("@domain.com"), None);
        assert_eq!(DomainAgeChecker::extract_domain("user@"), None);
        assert_eq!(
            DomainAgeChecker::extract_domain("user@invalid_chars!"),
            None
        );
    }

    #[test]
    fn test_extract_root_domain() {
        let checker = DomainAgeChecker::new(10, false);

        // Basic domains
        assert_eq!(checker.extract_root_domain("example.com"), "example.com");
        assert_eq!(checker.extract_root_domain("google.com"), "google.com");

        // Subdomains
        assert_eq!(
            checker.extract_root_domain("email.nationalgeographic.com"),
            "nationalgeographic.com"
        );
        assert_eq!(checker.extract_root_domain("mail.google.com"), "google.com");
        assert_eq!(
            checker.extract_root_domain("sub.domain.example.org"),
            "example.org"
        );

        // Two-part TLDs
        assert_eq!(
            checker.extract_root_domain("example.co.uk"),
            "example.co.uk"
        );
        assert_eq!(
            checker.extract_root_domain("mail.example.co.uk"),
            "example.co.uk"
        );
        assert_eq!(
            checker.extract_root_domain("test.company.com.au"),
            "company.com.au"
        );

        // Edge cases
        assert_eq!(checker.extract_root_domain("single"), "single");
        assert_eq!(checker.extract_root_domain("a.b"), "a.b");
    }

    async fn insert(checker: &DomainAgeChecker, domain: &str, entry: CacheEntry) {
        checker
            .cache
            .write()
            .await
            .insert(domain.to_string(), entry);
    }

    fn failure(age: Duration) -> CacheEntry {
        CacheEntry::Failed {
            error: "no WHOIS data".to_string(),
            at: SystemTime::now() - age,
        }
    }

    #[tokio::test]
    async fn test_failed_lookups_are_cached_for_an_hour() {
        // A mock lookup always succeeds, so an error proves the cache answered
        let checker = DomainAgeChecker::new(10, true);
        insert(
            &checker,
            "failing.example",
            failure(Duration::from_secs(60)),
        )
        .await;
        let err = checker
            .get_domain_info("failing.example")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cached failure"), "{err}");

        // After the failure TTL the domain is looked up again
        insert(&checker, "failing.example", failure(FAILURE_TTL * 2)).await;
        assert!(checker.get_domain_info("failing.example").await.is_ok());
    }

    #[tokio::test]
    async fn test_clones_and_timeouts_share_the_cache() {
        let checker = DomainAgeChecker::new(5, true);
        let shared = checker.with_timeout(30);
        checker.get_domain_info("google.com").await.unwrap();
        assert!(shared.cache.read().await.contains_key("google.com"));
        assert!(checker
            .clone()
            .cache
            .read()
            .await
            .contains_key("google.com"));
    }

    #[test]
    fn test_make_room_drops_expired_then_oldest() {
        let now = SystemTime::now();
        let known = |age: Duration| {
            CacheEntry::Known(DomainInfo {
                domain: String::new(),
                creation_date: None,
                age_days: Some(1),
                cached_at: now - age,
            })
        };

        let fresh = |n: usize| -> HashMap<String, CacheEntry> {
            (0..n)
                .map(|i| {
                    (
                        format!("d{i}.example"),
                        known(Duration::from_secs(i as u64)),
                    )
                })
                .collect()
        };

        // Dropping the expired entries makes enough room: all fresh ones stay
        let mut cache = fresh(CACHE_CAPACITY - 2);
        cache.insert("stale.example".to_string(), known(CACHE_TTL * 2));
        cache.insert(
            "stale-failure.example".to_string(),
            failure(FAILURE_TTL * 2),
        );
        DomainAgeChecker::make_room(&mut cache);
        assert_eq!(cache.len(), CACHE_CAPACITY - 2);
        assert!(!cache.contains_key("stale.example"));
        assert!(!cache.contains_key("stale-failure.example"));

        // All fresh: the oldest tenth goes
        let mut cache = fresh(CACHE_CAPACITY);
        DomainAgeChecker::make_room(&mut cache);
        assert_eq!(cache.len(), CACHE_CAPACITY - CACHE_CAPACITY / 10);
        assert!(cache.contains_key("d0.example"));
        assert!(!cache.contains_key(&format!("d{}.example", CACHE_CAPACITY - 1)));
    }

    #[tokio::test]
    async fn test_mock_domain_age() {
        let checker = DomainAgeChecker::new(10, true);

        // Test young domain
        assert!(checker.is_domain_young("psybook.info", 120).await.unwrap());
        assert!(!checker.is_domain_young("psybook.info", 60).await.unwrap());

        // Test old domain
        assert!(!checker.is_domain_young("google.com", 120).await.unwrap());
    }
}
