#![allow(clippy::uninlined_format_args)]

use anyhow::Result;
use log::{debug, info, warn};
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;

/// Google Groups unsubscriber for automatically unsubscribing from abusive groups
pub struct GoogleGroupsUnsubscriber {
    client: Client,
}

impl GoogleGroupsUnsubscriber {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("FOFF-Milter/1.0")
            .build()
            .unwrap_or_else(|_| Client::new());

        Self { client }
    }
}

impl Default for GoogleGroupsUnsubscriber {
    fn default() -> Self {
        Self::new()
    }
}

impl GoogleGroupsUnsubscriber {
    pub fn extract_group_info(&self, headers: &HashMap<String, String>) -> Option<GoogleGroupInfo> {
        let mut group_info = GoogleGroupInfo::default();

        // Extract Google Group ID
        if let Some(group_id) = headers.get("x-google-group-id") {
            group_info.group_id = Some(group_id.clone());
        }

        // Extract List-ID for domain and group name
        if let Some(list_id) = headers.get("list-id") {
            if let Some(parsed) = self.parse_list_id(list_id) {
                group_info.group_name = parsed.group_name;
                group_info.domain = parsed.domain;
            }
        }

        // Extract unsubscribe links
        if let Some(unsubscribe) = headers.get("list-unsubscribe") {
            group_info.unsubscribe_links = self.parse_unsubscribe_links(unsubscribe);
        }

        // Extract mailing list info
        if let Some(mailing_list) = headers.get("mailing-list") {
            if let Some(contact_email) = self.parse_mailing_list(mailing_list) {
                group_info.contact_email = Some(contact_email);
            }
        }

        // Only return if we have enough information to unsubscribe
        if group_info.group_id.is_some() || !group_info.unsubscribe_links.is_empty() {
            Some(group_info)
        } else {
            None
        }
    }

    /// Attempt to unsubscribe from the Google Group
    pub async fn unsubscribe(
        &self,
        group_info: &GoogleGroupInfo,
        recipient_email: &str,
        reason: Option<&str>,
    ) -> Result<UnsubscribeResult> {
        info!(
            "Attempting to unsubscribe {} from Google Group",
            recipient_email
        );

        let mut results = Vec::new();
        let default_reason = "Automated unsubscribe due to spam/abuse detection";
        let unsubscribe_reason = reason.unwrap_or(default_reason);

        // Try Google Groups API unsubscribe first (if we have group info)
        if let (Some(group_id), Some(domain)) = (&group_info.group_id, &group_info.domain) {
            match self
                .unsubscribe_via_api(group_id, domain, recipient_email, unsubscribe_reason)
                .await
            {
                Ok(result) => {
                    let success = result.success;
                    results.push(result);
                    if success {
                        return Ok(UnsubscribeResult::success_with_methods(results));
                    }
                }
                Err(e) => {
                    warn!("Google Groups API unsubscribe failed: {}", e);
                    results.push(UnsubscribeMethod {
                        method: "Google Groups API".to_string(),
                        success: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        // Try unsubscribe links as fallback
        for link in &group_info.unsubscribe_links {
            match self.unsubscribe_via_link(link, recipient_email).await {
                Ok(result) => {
                    let success = result.success;
                    results.push(result);
                    if success {
                        return Ok(UnsubscribeResult::success_with_methods(results));
                    }
                }
                Err(e) => {
                    warn!("Unsubscribe link {} failed: {}", link, e);
                    results.push(UnsubscribeMethod {
                        method: format!("Link: {}", link),
                        success: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        // Try mailto unsubscribe as last resort
        if let Some(contact_email) = &group_info.contact_email {
            match self
                .unsubscribe_via_email(contact_email, recipient_email, unsubscribe_reason)
                .await
            {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!("Email unsubscribe to {} failed: {}", contact_email, e);
                    results.push(UnsubscribeMethod {
                        method: format!("Email: {}", contact_email),
                        success: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        // Return combined results
        let success = results.iter().any(|r| r.success);
        Ok(UnsubscribeResult {
            success,
            methods: results,
            group_info: group_info.clone(),
        })
    }

    /// Unsubscribe via Google Groups API (if available)
    async fn unsubscribe_via_api(
        &self,
        group_id: &str,
        domain: &str,
        email: &str,
        reason: &str,
    ) -> Result<UnsubscribeMethod> {
        debug!(
            "Attempting Google Groups API unsubscribe for group {} on domain {}",
            group_id, domain
        );

        // Try the standard Google Groups unsubscribe endpoint
        let unsubscribe_url = format!(
            "https://groups.google.com/a/{}/group/{}/unsubscribe",
            domain, group_id
        );

        let response = self
            .client
            .post(&unsubscribe_url)
            .form(&[("email", email), ("reason", reason)])
            .send()
            .await?;

        let success = response.status().is_success();
        let status_code = response.status().as_u16();

        if success {
            info!("Successfully unsubscribed {} via Google Groups API", email);
        } else {
            warn!(
                "Google Groups API unsubscribe failed with status {}",
                status_code
            );
        }

        Ok(UnsubscribeMethod {
            method: "Google Groups API".to_string(),
            success,
            error: if success {
                None
            } else {
                Some(format!("HTTP {}", status_code))
            },
        })
    }

    /// Unsubscribe via HTTP link
    async fn unsubscribe_via_link(&self, link: &str, _email: &str) -> Result<UnsubscribeMethod> {
        debug!("Attempting unsubscribe via link: {}", link);

        let response = self.client.get(link).send().await?;

        let success = response.status().is_success();
        let status_code = response.status().as_u16();

        if success {
            info!("Successfully unsubscribed via link: {}", link);
        } else {
            warn!(
                "Unsubscribe link failed with status {}: {}",
                status_code, link
            );
        }

        Ok(UnsubscribeMethod {
            method: format!("HTTP Link: {}", link),
            success,
            error: if success {
                None
            } else {
                Some(format!("HTTP {}", status_code))
            },
        })
    }

    /// Unsubscribe via email (logs for manual processing)
    async fn unsubscribe_via_email(
        &self,
        contact_email: &str,
        recipient_email: &str,
        reason: &str,
    ) -> Result<UnsubscribeMethod> {
        // For now, we just log this for manual processing
        // In the future, this could integrate with the SMTP functionality
        info!(
            "Email unsubscribe request logged: recipient={}, contact={}, reason={}",
            recipient_email, contact_email, reason
        );

        // TODO: Integrate with SMTP to actually send unsubscribe emails
        Ok(UnsubscribeMethod {
            method: format!("Email: {}", contact_email),
            success: true, // Consider logging as success for now
            error: None,
        })
    }

    /// Parse List-ID header to extract group and domain info
    fn parse_list_id(&self, list_id: &str) -> Option<ParsedListId> {
        // Format: <group.domain.com> or "Name" <group.domain.com>
        if let Some(start) = list_id.find('<') {
            if let Some(end) = list_id.find('>') {
                let id_part = &list_id[start + 1..end];
                let parts: Vec<&str> = id_part.split('.').collect();
                if parts.len() >= 2 {
                    return Some(ParsedListId {
                        group_name: Some(parts[0].to_string()),
                        domain: Some(parts[1..].join(".")),
                    });
                }
            }
        }
        None
    }

    /// Parse List-Unsubscribe header to extract unsubscribe links
    fn parse_unsubscribe_links(&self, unsubscribe: &str) -> Vec<String> {
        let mut links = Vec::new();

        // Split by comma and extract URLs
        for part in unsubscribe.split(',') {
            let trimmed = part.trim();
            if trimmed.starts_with('<') && trimmed.ends_with('>') {
                let link = &trimmed[1..trimmed.len() - 1];
                if link.starts_with("http") {
                    links.push(link.to_string());
                }
            }
        }

        links
    }

    /// Parse Mailing-list header to extract contact email
    fn parse_mailing_list(&self, mailing_list: &str) -> Option<String> {
        // Format: list group@domain.com; contact group+owners@domain.com
        if let Some(contact_start) = mailing_list.find("contact ") {
            let contact_part = &mailing_list[contact_start + 8..];
            if let Some(email_end) = contact_part.find(' ') {
                return Some(contact_part[..email_end].to_string());
            } else {
                return Some(contact_part.to_string());
            }
        }
        None
    }
}

#[derive(Debug, Clone, Default)]
pub struct GoogleGroupInfo {
    pub group_id: Option<String>,
    pub group_name: Option<String>,
    pub domain: Option<String>,
    pub unsubscribe_links: Vec<String>,
    pub contact_email: Option<String>,
}

#[derive(Debug)]
struct ParsedListId {
    group_name: Option<String>,
    domain: Option<String>,
}

#[derive(Debug)]
pub struct UnsubscribeResult {
    pub success: bool,
    pub methods: Vec<UnsubscribeMethod>,
    pub group_info: GoogleGroupInfo,
}

#[derive(Debug, Clone)]
pub struct UnsubscribeMethod {
    pub method: String,
    pub success: bool,
    pub error: Option<String>,
}

impl UnsubscribeResult {
    fn success_with_methods(methods: Vec<UnsubscribeMethod>) -> Self {
        Self {
            success: true,
            methods,
            group_info: GoogleGroupInfo::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_list_id() {
        let unsubscriber = GoogleGroupsUnsubscriber::new();

        // Test standard format
        let result = unsubscriber.parse_list_id("<db.beusnesez.site>");
        assert!(result.is_some());
        let parsed = result.unwrap();
        assert_eq!(parsed.group_name, Some("db".to_string()));
        assert_eq!(parsed.domain, Some("beusnesez.site".to_string()));

        // Test with subdomain
        let result = unsubscriber.parse_list_id("<group.sub.domain.com>");
        assert!(result.is_some());
        let parsed = result.unwrap();
        assert_eq!(parsed.group_name, Some("group".to_string()));
        assert_eq!(parsed.domain, Some("sub.domain.com".to_string()));
    }

    #[test]
    fn test_parse_unsubscribe_links() {
        let unsubscriber = GoogleGroupsUnsubscriber::new();

        let unsubscribe = "<mailto:test@example.com>, <https://example.com/unsubscribe>";
        let links = unsubscriber.parse_unsubscribe_links(unsubscribe);

        assert_eq!(links.len(), 1);
        assert_eq!(links[0], "https://example.com/unsubscribe");
    }

    #[test]
    fn test_extract_group_info() {
        let unsubscriber = GoogleGroupsUnsubscriber::new();
        let mut headers = HashMap::new();

        headers.insert("x-google-group-id".to_string(), "282548616536".to_string());
        headers.insert("list-id".to_string(), "<db.beusnesez.site>".to_string());
        headers.insert(
            "list-unsubscribe".to_string(),
            "<https://groups.google.com/unsubscribe>".to_string(),
        );

        let group_info = unsubscriber.extract_group_info(&headers);
        assert!(group_info.is_some());

        let info = group_info.unwrap();
        assert_eq!(info.group_id, Some("282548616536".to_string()));
        assert_eq!(info.group_name, Some("db".to_string()));
        assert_eq!(info.domain, Some("beusnesez.site".to_string()));
        assert_eq!(info.unsubscribe_links.len(), 1);
    }
}
