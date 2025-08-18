use crate::filter::MailContext;
use std::collections::HashMap;

/// Handles reporting abuse to email service providers
pub struct AbuseReporter {
    // Configuration for different service providers
    service_configs: HashMap<String, ServiceConfig>,
}

#[derive(Clone)]
struct ServiceConfig {
    abuse_email: String,
    report_url: Option<String>,
    headers_template: String,
}

impl AbuseReporter {
    pub fn new() -> Self {
        let mut service_configs = HashMap::new();

        // SendGrid abuse reporting
        service_configs.insert(
            "sendgrid".to_string(),
            ServiceConfig {
                abuse_email: "abuse@sendgrid.com".to_string(),
                report_url: Some("https://sendgrid.com/report-abuse".to_string()),
                headers_template:
                    "Automated abuse report for phishing email sent through SendGrid infrastructure"
                        .to_string(),
            },
        );

        // Mailchimp abuse reporting
        service_configs.insert("mailchimp".to_string(), ServiceConfig {
            abuse_email: "abuse@mailchimp.com".to_string(),
            report_url: Some("https://mailchimp.com/contact/abuse/".to_string()),
            headers_template: "Automated abuse report for phishing email sent through Mailchimp infrastructure".to_string(),
        });

        // Constant Contact abuse reporting
        service_configs.insert("constantcontact".to_string(), ServiceConfig {
            abuse_email: "abuse@constantcontact.com".to_string(),
            report_url: None,
            headers_template: "Automated abuse report for phishing email sent through Constant Contact infrastructure".to_string(),
        });

        // Mailgun abuse reporting
        service_configs.insert(
            "mailgun".to_string(),
            ServiceConfig {
                abuse_email: "abuse@mailgun.com".to_string(),
                report_url: Some("https://www.mailgun.com/report-abuse/".to_string()),
                headers_template:
                    "Automated abuse report for phishing email sent through Mailgun infrastructure"
                        .to_string(),
            },
        );

        Self { service_configs }
    }

    /// Report abuse to the specified service provider
    pub async fn report_abuse(
        &self,
        service_provider: &str,
        context: &MailContext,
        include_headers: bool,
        include_body: bool,
        custom_message: Option<&str>,
    ) -> Result<(), AbuseReportError> {
        let service_config = self
            .service_configs
            .get(service_provider)
            .ok_or_else(|| AbuseReportError::UnsupportedProvider(service_provider.to_string()))?;

        let report = self.generate_abuse_report(
            service_config,
            context,
            include_headers,
            include_body,
            custom_message,
        );

        // Log the abuse report (in production, this would send the actual report)
        log::info!("🚨 ABUSE REPORT GENERATED for {service_provider}:");
        log::info!("To: {}", service_config.abuse_email);
        if let Some(url) = &service_config.report_url {
            log::info!("Report URL: {url}");
        }
        log::info!("Report Content:\n{report}");

        // TODO: In production, implement actual email sending or HTTP POST to abuse endpoints
        // For now, we log the report for manual submission

        Ok(())
    }

    fn generate_abuse_report(
        &self,
        service_config: &ServiceConfig,
        context: &MailContext,
        include_headers: bool,
        include_body: bool,
        custom_message: Option<&str>,
    ) -> String {
        let mut report = String::new();

        // Report header
        report.push_str(&format!("Subject: {}\n\n", service_config.headers_template));

        // Custom message if provided
        if let Some(message) = custom_message {
            report.push_str(&format!("{message}\n\n"));
        }

        // Basic email information
        report.push_str("PHISHING EMAIL DETAILS:\n");
        report.push_str("========================\n\n");

        if let Some(sender) = &context.sender {
            report.push_str(&format!("Sender: {sender}\n"));
        }

        if let Some(from_header) = &context.from_header {
            report.push_str(&format!("From Header: {from_header}\n"));
        }

        report.push_str(&format!("Recipients: {}\n", context.recipients.join(", ")));

        if let Some(subject) = &context.subject {
            report.push_str(&format!("Subject: {subject}\n"));
        }

        // Include headers if requested
        if include_headers {
            report.push_str("\nEMAIL HEADERS:\n");
            report.push_str("==============\n");
            for (header_name, header_value) in &context.headers {
                report.push_str(&format!("{header_name}: {header_value}\n"));
            }
        }

        // Include body if requested (usually not recommended for privacy)
        if include_body {
            if let Some(body) = &context.body {
                report.push_str("\nEMAIL BODY:\n");
                report.push_str("===========\n");
                report.push_str(body);
                report.push('\n');
            }
        }

        // Add detection information
        report.push_str("\nDETECTION INFORMATION:\n");
        report.push_str("=====================\n");
        report.push_str("This email was automatically detected as phishing/spam abuse of your email infrastructure.\n");
        report.push_str(
            "Please investigate and take appropriate action against the abusing account.\n\n",
        );

        // Add timestamp
        report.push_str(&format!(
            "Report generated: {}\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));
        report.push_str("Generated by: FOFF Milter (https://github.com/mwjohnson/foff-milter)\n");

        report
    }

    /// Get list of supported service providers
    pub fn supported_providers(&self) -> Vec<String> {
        self.service_configs.keys().cloned().collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AbuseReportError {
    #[error("Unsupported service provider: {0}")]
    UnsupportedProvider(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl Default for AbuseReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_abuse_report_generation() {
        let reporter = AbuseReporter::new();

        // Create test context
        let mut headers = HashMap::new();
        headers.insert(
            "from".to_string(),
            "Terry S <terrysmith7987@aol.com>".to_string(),
        );
        headers.insert("reply-to".to_string(), "terrysmith7987@aol.com".to_string());
        headers.insert(
            "received".to_string(),
            "from vsvhrrcf.outbound-mail.sendgrid.net".to_string(),
        );

        let context = MailContext {
            sender: Some("bounces+55266851-93ca-robert=example.com@sendgrid.net".to_string()),
            recipients: vec!["victim@example.com".to_string()],
            subject: Some("Order Confirmation".to_string()),
            body: Some("Phishing email content".to_string()),
            headers,
            from_header: Some("terrysmith7987@aol.com".to_string()),
            helo: Some("sendgrid.net".to_string()),
            hostname: Some("vsvhrrcf.outbound-mail.sendgrid.net".to_string()),
            mailer: None,
        };

        // Test SendGrid abuse reporting
        let result = reporter
            .report_abuse(
                "sendgrid",
                &context,
                true,  // include headers
                false, // don't include body for privacy
                Some("This is a test abuse report for SendGrid phishing"),
            )
            .await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_supported_providers() {
        let reporter = AbuseReporter::new();
        let providers = reporter.supported_providers();

        assert!(providers.contains(&"sendgrid".to_string()));
        assert!(providers.contains(&"mailchimp".to_string()));
        assert!(providers.contains(&"constantcontact".to_string()));
        assert!(providers.contains(&"mailgun".to_string()));
    }

    #[tokio::test]
    async fn test_unsupported_provider() {
        let reporter = AbuseReporter::new();
        let context = MailContext {
            sender: Some("test@example.com".to_string()),
            recipients: vec!["victim@example.com".to_string()],
            subject: Some("Test".to_string()),
            body: None,
            headers: HashMap::new(),
            from_header: None,
            helo: None,
            hostname: None,
            mailer: None,
        };

        let result = reporter
            .report_abuse("unsupported", &context, true, false, None)
            .await;
        assert!(matches!(
            result,
            Err(AbuseReportError::UnsupportedProvider(_))
        ));
    }
}
