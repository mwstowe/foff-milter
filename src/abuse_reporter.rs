use crate::filter::MailContext;
use crate::legacy_config::SmtpConfig;
use lettre::message::{header, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use std::collections::HashMap;
use std::time::Duration;

/// Handles reporting abuse to email service providers
pub struct AbuseReporter {
    // Configuration for different service providers
    service_configs: HashMap<String, ServiceConfig>,
    // SMTP configuration for sending emails
    smtp_config: Option<SmtpConfig>,
}

#[derive(Clone)]
struct ServiceConfig {
    abuse_email: String,
    report_url: Option<String>,
    headers_template: String,
}

impl AbuseReporter {
    pub fn new() -> Self {
        Self::with_smtp_config(None)
    }

    pub fn with_smtp_config(smtp_config: Option<SmtpConfig>) -> Self {
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

        Self {
            service_configs,
            smtp_config,
        }
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

        let report_body = self.generate_abuse_report(
            service_config,
            context,
            include_headers,
            include_body,
            custom_message,
        );

        let subject = service_config.headers_template.clone();

        // Try to send email if SMTP is configured, otherwise log for manual submission
        if let Some(smtp_config) = &self.smtp_config {
            match self
                .send_email_report(
                    smtp_config,
                    &service_config.abuse_email,
                    &subject,
                    &report_body,
                )
                .await
            {
                Ok(()) => {
                    log::info!(
                        "✅ ABUSE REPORT SENT to {service_provider} ({}):",
                        service_config.abuse_email
                    );
                    log::info!("Subject: {subject}");
                    if let Some(url) = &service_config.report_url {
                        log::info!("Report URL: {url}");
                    }
                    log::debug!("Report content:\n{report_body}");
                }
                Err(e) => {
                    log::error!("❌ FAILED to send abuse report to {service_provider}: {e}");
                    log::warn!("📧 MANUAL SUBMISSION REQUIRED:");
                    log::warn!("To: {}", service_config.abuse_email);
                    log::warn!("Subject: {subject}");
                    log::info!("Report content:\n{report_body}");
                    return Err(e);
                }
            }
        } else {
            // No SMTP configured, log for manual submission
            log::warn!("📧 SMTP NOT CONFIGURED - MANUAL SUBMISSION REQUIRED:");
            log::warn!("🚨 ABUSE REPORT for {service_provider}:");
            log::warn!("To: {}", service_config.abuse_email);
            log::warn!("Subject: {subject}");
            if let Some(url) = &service_config.report_url {
                log::warn!("Report URL: {url}");
            }
            log::info!("Report content:\n{report_body}");
        }

        Ok(())
    }

    async fn send_email_report(
        &self,
        smtp_config: &SmtpConfig,
        to_email: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), AbuseReportError> {
        // Build the email message
        let from_name = smtp_config.from_name.as_deref().unwrap_or("FOFF Milter");
        let from_address = format!("{} <{}>", from_name, smtp_config.from_email);

        let email = Message::builder()
            .from(
                from_address.parse().map_err(|e| {
                    AbuseReportError::ConfigError(format!("Invalid from address: {e}"))
                })?,
            )
            .to(to_email
                .parse()
                .map_err(|e| AbuseReportError::ConfigError(format!("Invalid to address: {e}")))?)
            .subject(subject)
            .header(header::ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .map_err(|e| AbuseReportError::ConfigError(format!("Failed to build email: {e}")))?;

        // Configure SMTP transport (simplified - lettre will handle TLS automatically)
        let port = smtp_config.port.unwrap_or(587); // Default to STARTTLS port
        let timeout = Duration::from_secs(smtp_config.timeout_seconds.unwrap_or(30));

        let mut transport_builder = SmtpTransport::relay(&smtp_config.server)
            .map_err(|e| AbuseReportError::NetworkError(format!("SMTP relay error: {e}")))?
            .port(port)
            .timeout(Some(timeout));

        // lettre automatically handles STARTTLS for port 587
        // and SSL/TLS for port 465

        // Add authentication if configured
        if let (Some(username), Some(password)) = (&smtp_config.username, &smtp_config.password) {
            transport_builder =
                transport_builder.credentials(Credentials::new(username.clone(), password.clone()));
        }

        let mailer = transport_builder.build();

        // Send the email
        mailer
            .send(&email)
            .map_err(|e| AbuseReportError::NetworkError(format!("Failed to send email: {e}")))?;

        Ok(())
    }

    fn generate_abuse_report(
        &self,
        _service_config: &ServiceConfig,
        context: &MailContext,
        include_headers: bool,
        include_body: bool,
        custom_message: Option<&str>,
    ) -> String {
        let mut report = String::new();

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

        // Test SendGrid abuse reporting (will log since no SMTP configured)
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

    #[test]
    fn test_smtp_config_creation() {
        let smtp_config = SmtpConfig {
            server: "smtp.example.com".to_string(),
            port: Some(587),
            username: Some("user@example.com".to_string()),
            password: Some("password".to_string()),
            from_email: "noreply@example.com".to_string(),
            from_name: Some("Test Milter".to_string()),
            use_tls: Some(true),
            timeout_seconds: Some(30),
        };

        let reporter = AbuseReporter::with_smtp_config(Some(smtp_config));
        assert_eq!(reporter.supported_providers().len(), 4);
    }
}
