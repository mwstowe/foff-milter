use reqwest::Client;
use std::time::Duration;
use url::Url;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

pub struct UrlResolver {
    client: Client,
    max_redirects: u8,
    cache: Arc<RwLock<HashMap<String, String>>>,
}

impl UrlResolver {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(5)) // Reduced timeout for faster response
            .user_agent("FOFF-Milter/0.7.8")
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            client,
            max_redirects: 3, // Reduced for performance
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get consolidated list of known shorteners
    pub fn get_shorteners() -> &'static [&'static str] {
        &[
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", 
            "short.link", "is.gd", "v.gd", "tiny.cc", "rb.gy", 
            "cutt.ly", "shorturl.at", "1url.com", "u.to", "tny.sh"
        ]
    }

    /// Get domains that should be excluded from shortener detection
    pub fn get_excluded_domains() -> &'static [&'static str] {
        &[
            "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
            "youtube.com", "snapchat.com", "tiktok.com", "pinterest.com",
            "reddit.com", "discord.com", "telegram.org", "whatsapp.com"
        ]
    }

    /// Quick sync check if URL is a known shortener
    pub fn is_shortener(&self, url: &str) -> bool {
        if let Ok(parsed) = Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                // Check excluded domains first
                if Self::get_excluded_domains()
                    .iter()
                    .any(|&d| host == d || host.ends_with(&format!(".{}", d)))
                {
                    return false;
                }
                
                // Check shortener domains
                return Self::get_shorteners()
                    .iter()
                    .any(|&s| host == s || host.ends_with(&format!(".{}", s)));
            }
        }
        false
    }

    /// Quick sync resolution attempt (non-blocking)
    pub fn try_resolve_sync(&self, url: &str) -> Option<String> {
        // Check cache first
        if let Ok(cache) = self.cache.try_read() {
            if let Some(resolved) = cache.get(url) {
                return Some(resolved.clone());
            }
        }
        None
    }

    /// Async resolution with caching
    pub async fn resolve_url(&self, url: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(resolved) = cache.get(url) {
                return Ok(resolved.clone());
            }
        }

        let mut current_url = url.to_string();
        let mut redirect_count = 0;

        while redirect_count < self.max_redirects {
            let response = self.client.head(&current_url).send().await?;

            if response.status().is_redirection() {
                if let Some(location) = response.headers().get("location") {
                    let location_str = location.to_str()?;
                    current_url = if location_str.starts_with("http") {
                        location_str.to_string()
                    } else {
                        let base = Url::parse(&current_url)?;
                        base.join(location_str)?.to_string()
                    };
                    redirect_count += 1;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Cache the result
        {
            let mut cache = self.cache.write().await;
            cache.insert(url.to_string(), current_url.clone());
        }

        Ok(current_url)
    }

    /// Extract domain from URL
    pub fn extract_domain(&self, url: &str) -> Option<String> {
        Url::parse(url).ok()?.host_str().map(|h| h.to_lowercase())
    }

    /// Spawn background resolution task (non-blocking)
    pub fn resolve_background(&self, url: String) {
        let resolver = self.clone();
        tokio::spawn(async move {
            if let Err(e) = resolver.resolve_url(&url).await {
                log::debug!("Background URL resolution failed for {}: {}", url, e);
            }
        });
    }
}

impl Clone for UrlResolver {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            max_redirects: self.max_redirects,
            cache: Arc::clone(&self.cache),
        }
    }
}

impl Default for UrlResolver {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            let client = Client::new();
            Self {
                client,
                max_redirects: 3,
                cache: Arc::new(RwLock::new(HashMap::new())),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_shortener() {
        let resolver = UrlResolver::default();

        assert!(resolver.is_shortener("https://bit.ly/abc123"));
        assert!(resolver.is_shortener("http://tinyurl.com/test"));
        assert!(resolver.is_shortener("https://t.co/xyz789"));
        assert!(!resolver.is_shortener("https://google.com"));
        assert!(!resolver.is_shortener("https://example.com/path"));
    }

    #[test]
    fn test_extract_domain() {
        let resolver = UrlResolver::default();

        assert_eq!(
            resolver.extract_domain("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            resolver.extract_domain("http://bit.ly/abc123"),
            Some("bit.ly".to_string())
        );
        assert_eq!(resolver.extract_domain("invalid-url"), None);
    }
}
