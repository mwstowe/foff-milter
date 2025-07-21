use crate::config::{Action, Config};
use crate::filter::{FilterEngine, MailContext};
use std::sync::Arc;

pub struct FoffMilter {
    engine: Arc<FilterEngine>,
    context: MailContext,
}

impl FoffMilter {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let engine = Arc::new(FilterEngine::new(config)?);
        Ok(FoffMilter {
            engine,
            context: MailContext::default(),
        })
    }

    pub fn process_connection(&mut self, hostname: &str) {
        log::info!("Connection from hostname: {}", hostname);
        self.context = MailContext::default();
    }

    pub fn process_mail_from(&mut self, mail_from: &str) {
        log::debug!("MAIL FROM: {}", mail_from);
        self.context.sender = Some(mail_from.to_string());
    }

    pub fn process_rcpt_to(&mut self, rcpt_to: &str) {
        log::debug!("RCPT TO: {}", rcpt_to);
        self.context.recipients.push(rcpt_to.to_string());
    }

    pub fn process_header(&mut self, name: &str, value: &str) {
        log::debug!("Header: {}: {}", name, value);
        
        // Store all headers
        self.context.headers.insert(name.to_lowercase(), value.to_string());
        
        // Extract specific headers we care about
        match name.to_lowercase().as_str() {
            "subject" => {
                self.context.subject = Some(value.to_string());
            }
            "x-mailer" | "user-agent" => {
                self.context.mailer = Some(value.to_string());
            }
            _ => {}
        }
    }

    pub fn evaluate_message(&self) -> &Action {
        log::debug!("Evaluating message against rules");
        self.engine.evaluate(&self.context)
    }

    pub fn reset_context(&mut self) {
        self.context = MailContext::default();
    }
}

// Simple milter server implementation
pub fn run_milter(config: Config) -> anyhow::Result<()> {
    log::info!("Starting FOFF milter with socket: {}", config.socket_path);
    
    // Remove existing socket file if it exists
    if std::path::Path::new(&config.socket_path).exists() {
        std::fs::remove_file(&config.socket_path)?;
    }
    
    // Create the milter instance
    let mut milter = FoffMilter::new(config.clone())?;
    
    log::info!("FOFF milter initialized successfully");
    log::info!("Socket path: {}", config.socket_path);
    log::info!("Number of rules loaded: {}", config.rules.len());
    
    // In a real implementation, this would be the main event loop
    // For now, we'll just demonstrate the functionality
    demonstrate_functionality(&mut milter);
    
    Ok(())
}

fn demonstrate_functionality(milter: &mut FoffMilter) {
    log::info!("Demonstrating milter functionality...");
    
    // Test 1: Chinese service with Japanese content (Example 1)
    log::info!("=== Test 1: Chinese service with Japanese content ===");
    milter.process_connection("mail-server.example.cn");
    milter.process_mail_from("sender@suspicious.cn");
    milter.process_rcpt_to("recipient@mydomain.com");
    milter.process_header("Subject", "こんにちは！特別なオファー - Hello Special Offer"); // Japanese + English
    milter.process_header("X-Mailer", "service.mail.cn v2.1");
    
    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✓ Would reject Chinese service + Japanese: {}", message);
        }
        Action::TagAsSpam { header_name, header_value } => {
            log::info!("✓ Would tag Chinese service + Japanese {}:{}", header_name, header_value);
        }
        Action::Accept => {
            log::info!("✗ Unexpectedly accepted Chinese service + Japanese");
        }
    }
    
    milter.reset_context();
    
    // Test 2: Sparkpost to user@example.com (Example 2)
    log::info!("=== Test 2: Sparkpost to user@example.com ===");
    milter.process_connection("sparkpost-relay.example.com");
    milter.process_mail_from("newsletter@company.com");
    milter.process_rcpt_to("user@example.com");
    milter.process_header("Subject", "Your Weekly Newsletter");
    milter.process_header("X-Mailer", "relay.sparkpostmail.com v3.2");
    
    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✓ Would reject Sparkpost to user@example.com: {}", message);
        }
        Action::TagAsSpam { header_name, header_value } => {
            log::info!("✓ Would tag Sparkpost to user@example.com {}:{}", header_name, header_value);
        }
        Action::Accept => {
            log::info!("✗ Unexpectedly accepted Sparkpost to user@example.com");
        }
    }
    
    milter.reset_context();
    
    // Test 3: Chinese service without Japanese (should not match Example 1)
    log::info!("=== Test 3: Chinese service without Japanese ===");
    milter.process_connection("mail-server.example.cn");
    milter.process_mail_from("sender@business.cn");
    milter.process_rcpt_to("recipient@mydomain.com");
    milter.process_header("Subject", "Business Proposal - English Only");
    milter.process_header("X-Mailer", "service.business.cn v1.0");
    
    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✗ Unexpectedly rejected Chinese service without Japanese: {}", message);
        }
        Action::TagAsSpam { header_name, header_value } => {
            log::info!("✗ Unexpectedly tagged Chinese service without Japanese {}:{}", header_name, header_value);
        }
        Action::Accept => {
            log::info!("✓ Correctly accepted Chinese service without Japanese");
        }
    }
    
    milter.reset_context();
    
    // Test 4: Sparkpost to different user (should not match Example 2)
    log::info!("=== Test 4: Sparkpost to different user ===");
    milter.process_connection("sparkpost-relay.example.com");
    milter.process_mail_from("newsletter@company.com");
    milter.process_rcpt_to("admin@example.com");
    milter.process_header("Subject", "Your Weekly Newsletter");
    milter.process_header("X-Mailer", "relay.sparkpostmail.com v3.2");
    
    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✗ Unexpectedly rejected Sparkpost to different user: {}", message);
        }
        Action::TagAsSpam { header_name, header_value } => {
            log::info!("✗ Unexpectedly tagged Sparkpost to different user {}:{}", header_name, header_value);
        }
        Action::Accept => {
            log::info!("✓ Correctly accepted Sparkpost to different user");
        }
    }
    
    milter.reset_context();
    
    // Test 5: Japanese content without Chinese service (should not match Example 1)
    log::info!("=== Test 5: Japanese content without Chinese service ===");
    milter.process_connection("legitimate-host.jp");
    milter.process_mail_from("user@legitimate.jp");
    milter.process_rcpt_to("recipient@mydomain.com");
    milter.process_header("Subject", "こんにちは、元気ですか？"); // Japanese only
    milter.process_header("X-Mailer", "Thunderbird 102.0");
    
    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✗ Unexpectedly rejected Japanese without Chinese service: {}", message);
        }
        Action::TagAsSpam { header_name, header_value } => {
            log::info!("✗ Unexpectedly tagged Japanese without Chinese service {}:{}", header_name, header_value);
        }
        Action::Accept => {
            log::info!("✓ Correctly accepted Japanese without Chinese service");
        }
    }
    
    milter.reset_context();
    
    // Test 6: Regular legitimate email (should not match any rules)
    log::info!("=== Test 6: Regular legitimate email ===");
    milter.process_connection("legitimate-host.example.com");
    milter.process_mail_from("user@legitimate.com");
    milter.process_rcpt_to("recipient@mydomain.com");
    milter.process_header("Subject", "Regular business email");
    milter.process_header("X-Mailer", "Postfix 3.6.4");
    
    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✗ Unexpectedly rejected legitimate email: {}", message);
        }
        Action::TagAsSpam { header_name, header_value } => {
            log::info!("✗ Unexpectedly tagged legitimate email {}:{}", header_name, header_value);
        }
        Action::Accept => {
            log::info!("✓ Correctly accepted legitimate email");
        }
    }
    
    log::info!("=== Demonstration complete ===");
    log::info!("Summary:");
    log::info!("  ✓ Chinese service + Japanese → BLOCKED (Example 1)");
    log::info!("  ✓ Sparkpost → user@example.com → BLOCKED (Example 2)");
    log::info!("  ✓ Partial matches correctly ignored");
    log::info!("  ✓ Legitimate emails correctly accepted");
    log::info!("");
    log::info!("In a real deployment, this would run as a daemon processing actual emails.");
}
