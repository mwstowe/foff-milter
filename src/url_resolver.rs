use reqwest::Client;
use std::time::Duration;
use url::Url;

pub struct UrlResolver {
    client: Client,
    max_redirects: u8,
    timeout_seconds: u64,
}

impl UrlResolver {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("FOFF-Milter/0.7.6")
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            client,
            max_redirects: 5,
            timeout_seconds: 10,
        })
    }

    /// Resolve a shortened URL to its final destination
    pub async fn resolve_url(&self, url: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut current_url = url.to_string();
        let mut redirect_count = 0;

        while redirect_count < self.max_redirects {
            // Make HEAD request to follow redirects
            let response = self.client.head(&current_url).send().await?;
            
            if response.status().is_redirection() {
                if let Some(location) = response.headers().get("location") {
                    let location_str = location.to_str()?;
                    
                    // Handle relative URLs
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

        Ok(current_url)
    }

    /// Check if a URL is a known shortener
    pub fn is_shortener(&self, url: &str) -> bool {
        let shorteners = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "short.link", "is.gd", "v.gd", "tiny.cc", "rb.gy",
            "cutt.ly", "shorturl.at", "1url.com", "u.to"
        ];
        
        if let Ok(parsed) = Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                return shorteners.iter().any(|&s| host.contains(s));
            }
        }
        
        shorteners.iter().any(|&s| url.contains(s))
    }

    /// Extract domain from URL
    pub fn extract_domain(&self, url: &str) -> Option<String> {
        Url::parse(url)
            .ok()?
            .host_str()
            .map(|h| h.to_lowercase())
    }
}

impl Default for UrlResolver {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            // Fallback if client creation fails
            let client = Client::new();
            Self {
                client,
                max_redirects: 5,
                timeout_seconds: 10,
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
        
        assert_eq!(resolver.extract_domain("https://example.com/path"), Some("example.com".to_string()));
        assert_eq!(resolver.extract_domain("http://bit.ly/abc123"), Some("bit.ly".to_string()));
        assert_eq!(resolver.extract_domain("invalid-url"), None);
    }
}
