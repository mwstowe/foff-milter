use regex::Regex;
use std::collections::HashMap;

pub struct EmailAnonymizer {
    domain_replacements: HashMap<String, String>,
    username_replacements: HashMap<String, String>,
    domain_counter: usize,
    username_counter: usize,
}

impl Default for EmailAnonymizer {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailAnonymizer {
    pub fn new() -> Self {
        Self {
            domain_replacements: HashMap::new(),
            username_replacements: HashMap::new(),
            domain_counter: 1,
            username_counter: 1,
        }
    }

    pub fn anonymize_email(&mut self, content: &str) -> String {
        let mut result = content.to_string();

        // Remove X-FOFF headers
        result = self.remove_xfoff_headers(&result);

        // Extract and anonymize email addresses
        result = self.anonymize_email_addresses(&result);

        // Anonymize common personal info patterns
        result = self.anonymize_personal_info(&result);

        result
    }

    fn remove_xfoff_headers(&self, content: &str) -> String {
        let re = Regex::new(r"(?m)^X-FOFF[^:]*:.*$\n?").unwrap();
        re.replace_all(content, "").to_string()
    }

    fn anonymize_email_addresses(&mut self, content: &str) -> String {
        let email_re =
            Regex::new(r"\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b").unwrap();

        email_re
            .replace_all(content, |caps: &regex::Captures| {
                let username = caps.get(1).unwrap().as_str();
                let domain = caps.get(2).unwrap().as_str();

                let anon_username = self.get_anonymous_username(username);
                let anon_domain = self.get_anonymous_domain(domain);

                format!("{}@{}", anon_username, anon_domain)
            })
            .to_string()
    }

    fn get_anonymous_username(&mut self, username: &str) -> String {
        if let Some(replacement) = self.username_replacements.get(username) {
            replacement.clone()
        } else {
            let replacement = format!("user{}", self.username_counter);
            self.username_counter += 1;
            self.username_replacements
                .insert(username.to_string(), replacement.clone());
            replacement
        }
    }

    fn get_anonymous_domain(&mut self, domain: &str) -> String {
        // Always use example.com for recipient domains
        if domain.contains("gmail.com")
            || domain.contains("yahoo.com")
            || domain.contains("hotmail.com")
            || domain.contains("outlook.com")
        {
            return "example.com".to_string();
        }

        if let Some(replacement) = self.domain_replacements.get(domain) {
            replacement.clone()
        } else {
            let replacement = if self.domain_counter == 1 {
                "example.com".to_string()
            } else {
                format!("example{}.com", self.domain_counter)
            };
            self.domain_counter += 1;
            self.domain_replacements
                .insert(domain.to_string(), replacement.clone());
            replacement
        }
    }

    fn anonymize_personal_info(&self, content: &str) -> String {
        let mut result = content.to_string();

        // Phone numbers
        let phone_re = Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap();
        result = phone_re.replace_all(&result, "555-123-4567").to_string();

        // SSN patterns
        let ssn_re = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
        result = ssn_re.replace_all(&result, "123-45-6789").to_string();

        // Credit card numbers (basic pattern)
        let cc_re = Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b").unwrap();
        result = cc_re
            .replace_all(&result, "1234-5678-9012-3456")
            .to_string();

        // Names in common patterns (Dear X, Hi X, etc.)
        let name_re = Regex::new(r"(?i)\b(dear|hi|hello|hey)\s+([A-Z][a-z]+)\b").unwrap();
        result = name_re.replace_all(&result, "$1 John").to_string();

        result
    }
}
