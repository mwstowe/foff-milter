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
    
    // Test 1: Original example - suspicious Chinese service
    log::info!("=== Test 1: Suspicious Chinese service ===");
    milter.process_connection("suspicious-host.example.com");
    milter.process_mail_from("sender@example.com");
    milter.process_rcpt_to("recipient@mydomain.com");
    milter.process_header("Subject", "Urgent business proposal");
    milter.process_header("X-Mailer", "service.spam.cn");
    
    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✓ Would reject email with message: {}", message);
        }
        Action::TagAsSpam { header_name, header_value } => {
            log::info!("✓ Would add spam header {}:{}", header_name, header_value);
        }
        Action::Accept => {
            log::info!("✓ Would accept email");
        }
    }
    
    milter.reset_context();
    
    // Test 2: Sparkmail with Japanese content (combination criteria)
    log::info!("=== Test 2: Sparkmail with Japanese content ===");
    milter.process_connection("sparkmail-host.example.com");
    milter.process_mail_from("promo@sparkmail.com");
    milter.process_rcpt_to("user@mydomain.com");
    milter.process_header("Subject", "こんにちは！特別オファー - Special Offer"); // Japanese + English
    milter.process_header("X-Mailer", "sparkmail.com bulk mailer v2.1");
    
    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✓ Would reject sparkmail+Japanese email: {}", message);
        }
        Action::TagAsSpam { header_name, header_value } => {
            log::info!("✓ Would tag sparkmail+Japanese email {}:{}", header_name, header_value);
        }
        Action::Accept => {
            log::info!("✓ Would accept sparkmail+Japanese email");
        }
    }
    
    milter.reset_context();
    
    // Test 3: Sparkmail without Japanese (should not match combination)
    log::info!("=== Test 3: Sparkmail without Japanese ===");
    milter.process_connection("sparkmail-host.example.com");
    milter.process_mail_from("promo@sparkmail.com");
    milter.process_rcpt_to("user@mydomain.com");
    milter.process_header("Subject", "Special Offer - English Only");
    milter.process_header("X-Mailer", "sparkmail.com bulk mailer v2.1");
    
    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✗ Unexpectedly rejected sparkmail-only email: {}", message);
        }
        Action::TagAsSpam { header_name, header_value } => {
            log::info!("✗ Unexpectedly tagged sparkmail-only email {}:{}", header_name, header_value);
        }
        Action::Accept => {
            log::info!("✓ Correctly accepted sparkmail-only email (no Japanese)");
        }
    }
    
    milter.reset_context();
    
    // Test 4: Japanese content without sparkmail (should not match combination)
    log::info!("=== Test 4: Japanese content without sparkmail ===");
    milter.process_connection("legitimate-host.example.com");
    milter.process_mail_from("user@legitimate.jp");
    milter.process_rcpt_to("recipient@mydomain.com");
    milter.process_header("Subject", "こんにちは、元気ですか？"); // Japanese only
    milter.process_header("X-Mailer", "Thunderbird 102.0");
    
    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✗ Unexpectedly rejected Japanese-only email: {}", message);
        }
        Action::TagAsSpam { header_name, header_value } => {
            log::info!("✗ Unexpectedly tagged Japanese-only email {}:{}", header_name, header_value);
        }
        Action::Accept => {
            log::info!("✓ Correctly accepted Japanese-only email (not sparkmail)");
        }
    }
    
    milter.reset_context();
    
    // Test 5: Regular legitimate email
    log::info!("=== Test 5: Regular legitimate email ===");
    milter.process_connection("legitimate-host.example.com");
    milter.process_mail_from("user@legitimate.com");
    milter.process_rcpt_to("recipient@mydomain.com");
    milter.process_header("Subject", "Regular business email");
    milter.process_header("X-Mailer", "Thunderbird 102.0");
    
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
    log::info!("In a real deployment, this would run as a daemon processing actual emails.");
}
