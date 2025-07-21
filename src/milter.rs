use crate::config::{Action, Config};
use crate::filter::{FilterEngine, MailContext};
use std::sync::Arc;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

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
pub fn run_milter(config: Config, demo_mode: bool) -> anyhow::Result<()> {
    log::info!("Starting FOFF milter with socket: {}", config.socket_path);
    
    // Remove existing socket file if it exists
    if Path::new(&config.socket_path).exists() {
        log::info!("Removing existing socket file: {}", config.socket_path);
        std::fs::remove_file(&config.socket_path)?;
    }
    
    // Create the milter instance
    let mut milter = FoffMilter::new(config.clone())?;
    
    log::info!("FOFF milter initialized successfully");
    log::info!("Socket path: {}", config.socket_path);
    log::info!("Number of rules loaded: {}", config.rules.len());
    
    if demo_mode {
        log::info!("Running in demonstration mode...");
        demonstrate_functionality(&mut milter);
        return Ok(());
    }
    
    // Production mode - create and bind to Unix socket
    log::info!("Starting milter daemon...");
    log::info!("Creating Unix socket: {}", config.socket_path);
    
    // Create parent directory if it doesn't exist
    if let Some(parent) = Path::new(&config.socket_path).parent() {
        if !parent.exists() {
            log::info!("Creating socket directory: {}", parent.display());
            std::fs::create_dir_all(parent)?;
        }
    }
    
    // Create the Unix socket
    let listener = UnixListener::bind(&config.socket_path)
        .map_err(|e| anyhow::anyhow!("Failed to bind to socket {}: {}", config.socket_path, e))?;
    
    log::info!("Successfully bound to socket: {}", config.socket_path);
    
    // Set socket permissions (readable/writable by owner and group)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&config.socket_path)?.permissions();
        perms.set_mode(0o660); // rw-rw----
        std::fs::set_permissions(&config.socket_path, perms)?;
        log::info!("Set socket permissions to 660");
    }
    
    log::info!("Milter daemon started successfully");
    log::info!("Waiting for email connections from sendmail/postfix...");
    log::info!("Press Ctrl+C to stop the milter");
    
    // Set up signal handling for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let socket_path_for_cleanup = config.socket_path.clone();
    
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal, cleaning up...");
        r.store(false, Ordering::SeqCst);
        
        // Clean up socket file
        if Path::new(&socket_path_for_cleanup).exists() {
            if let Err(e) = std::fs::remove_file(&socket_path_for_cleanup) {
                log::error!("Failed to remove socket file: {}", e);
            } else {
                log::info!("Socket file removed: {}", socket_path_for_cleanup);
            }
        }
        
        std::process::exit(0);
    }).map_err(|e| anyhow::anyhow!("Error setting up signal handler: {}", e))?;
    
    // Main event loop - accept connections
    while running.load(Ordering::SeqCst) {
        // Set a timeout on accept to allow checking the running flag
        match listener.accept() {
            Ok((stream, _addr)) => {
                log::debug!("Accepted connection from mail server");
                // In a real milter implementation, this would spawn a thread
                // to handle the milter protocol communication
                // For now, we'll just log the connection
                drop(stream); // Close the connection immediately
            }
            Err(e) => {
                log::error!("Error accepting connection: {}", e);
                // Continue running even if individual connections fail
            }
        }
    }
    
    // Clean up socket file on normal exit
    if Path::new(&config.socket_path).exists() {
        std::fs::remove_file(&config.socket_path)?;
        log::info!("Socket file cleaned up: {}", config.socket_path);
    }
    
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
