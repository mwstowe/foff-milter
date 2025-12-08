use regex::Regex;

pub struct EmailAnonymizer {
    recipient_email: Option<String>,
    recipient_domain: Option<String>,
    recipient_username: Option<String>,
}

impl Default for EmailAnonymizer {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailAnonymizer {
    pub fn new() -> Self {
        Self {
            recipient_email: None,
            recipient_domain: None,
            recipient_username: None,
        }
    }

    pub fn anonymize_email(&mut self, content: &str) -> String {
        let mut result = content.to_string();
        
        // Remove X-FOFF headers
        result = self.remove_xfoff_headers(&result);
        
        // Extract recipient info from To: header first
        self.extract_recipient_info(&result);
        
        // Only anonymize recipient references
        result = self.anonymize_recipient_references(&result);
        
        result
    }

    fn remove_xfoff_headers(&self, content: &str) -> String {
        let re = Regex::new(r"(?m)^X-FOFF[^:]*:.*$\n?").unwrap();
        re.replace_all(content, "").to_string()
    }

    fn extract_recipient_info(&mut self, content: &str) {
        // Extract from To: header
        let to_re = Regex::new(r"(?m)^To:\s*.*?([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})").unwrap();
        
        if let Some(caps) = to_re.captures(content) {
            let username = caps.get(1).unwrap().as_str();
            let domain = caps.get(2).unwrap().as_str();
            
            self.recipient_username = Some(username.to_string());
            self.recipient_domain = Some(domain.to_string());
            self.recipient_email = Some(format!("{}@{}", username, domain));
        }
    }

    fn anonymize_recipient_references(&self, content: &str) -> String {
        let mut result = content.to_string();
        
        if let (Some(recipient_email), Some(recipient_domain), Some(recipient_username)) = 
            (&self.recipient_email, &self.recipient_domain, &self.recipient_username) {
            
            // Replace recipient email with user@example.com
            result = result.replace(recipient_email, "user@example.com");
            
            // Replace recipient domain with example.com (but only when not part of sender info)
            result = self.replace_recipient_domain_carefully(&result, recipient_domain);
            
            // Replace recipient username in email body text
            result = self.anonymize_personal_references(&result, recipient_username);
        }
        
        result
    }

    fn replace_recipient_domain_carefully(&self, content: &str, recipient_domain: &str) -> String {
        let mut result = content.to_string();
        
        // Only replace in specific contexts where it's clearly the recipient
        // Replace in To: header
        let to_pattern = format!(r"(To:\s*[^@]+@){}", regex::escape(recipient_domain));
        let to_re = Regex::new(&to_pattern).unwrap();
        result = to_re.replace_all(&result, "${1}example.com").to_string();
        
        // Replace in envelope-to contexts
        let envelope_pattern = format!(r"(envelope-to[^@]+@){}", regex::escape(recipient_domain));
        let envelope_re = Regex::new(&envelope_pattern).unwrap();
        result = envelope_re.replace_all(&result, "${1}example.com").to_string();
        
        // Replace in for <user@domain> contexts
        let for_pattern = format!(r"(for\s+<[^@]+@){}", regex::escape(recipient_domain));
        let for_re = Regex::new(&for_pattern).unwrap();
        result = for_re.replace_all(&result, "${1}example.com").to_string();
        
        result
    }

    fn anonymize_personal_references(&self, content: &str, recipient_username: &str) -> String {
        let mut result = content.to_string();
        
        // Replace names in greetings (Dear X, Hi X, etc.) - but only if it matches recipient username
        let greeting_pattern = format!(r"(?i)\b(dear|hi|hello|hey)\s+{}\b", regex::escape(recipient_username));
        let greeting_re = Regex::new(&greeting_pattern).unwrap();
        result = greeting_re.replace_all(&result, "$1 John").to_string();
        
        // Replace phone numbers (generic anonymization)
        let phone_re = Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap();
        result = phone_re.replace_all(&result, "555-123-4567").to_string();
        
        // Replace SSN patterns
        let ssn_re = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
        result = ssn_re.replace_all(&result, "123-45-6789").to_string();
        
        // Replace credit card numbers
        let cc_re = Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b").unwrap();
        result = cc_re.replace_all(&result, "1234-5678-9012-3456").to_string();
        
        result
    }
}
