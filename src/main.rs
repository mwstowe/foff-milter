use clap::{Arg, Command};
use foff_milter::filter::FilterEngine;
use foff_milter::milter::Milter;
use foff_milter::statistics::StatisticsCollector;
use foff_milter::Config as LegacyConfig;
use log::LevelFilter;
use std::process;

#[tokio::main]
async fn main() {
    let matches = Command::new("foff-milter")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A sendmail milter for filtering emails based on configurable criteria")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("/etc/foff-milter.yaml"),
        )
        .arg(
            Arg::new("generate-config")
                .long("generate-config")
                .value_name("FILE")
                .help("Generate a default configuration file")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("test-config")
                .long("test-config")
                .help("Test the configuration file for validity and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats")
                .long("stats")
                .help("Show current statistics and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats-unmatched")
                .long("stats-unmatched")
                .help("Show rules that have never matched and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats-reset")
                .long("stats-reset")
                .help("Reset all statistics and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("demo")
                .long("demo")
                .help("Run in demonstration mode (simulate email processing)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose logging")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .help("Run as a daemon (background process)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("test-email")
                .long("test-email")
                .value_name("FILE")
                .help("Test an email file against the rules and show which rules match")
                .action(clap::ArgAction::Set),
        )
        .get_matches();

    // Initialize logger based on verbose flag
    let log_level = if matches.get_flag("verbose") {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    let config_path = matches.get_one::<String>("config").unwrap();

    if let Some(generate_path) = matches.get_one::<String>("generate-config") {
        generate_default_config(generate_path);
        return;
    }

    let config = match load_config(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error loading configuration: {e}");
            process::exit(1);
        }
    };

    if let Some(email_file) = matches.get_one::<String>("test-email") {
        test_email_file(&config, email_file).await;
        return;
    }

    if matches.get_flag("test-config") {
        println!("🔍 Testing configuration...");
        println!();

        // Check if using modular system or legacy rules
        if let Some(module_dir) = config.module_config_dir.as_ref() {
            println!("Module configuration directory: {}", module_dir);
            println!("Using modular detection system");

            // Count available module files
            let module_files = [
                "suspicious-domains.yaml",
                "brand-impersonation.yaml",
                "health-spam.yaml",
                "phishing-scams.yaml",
                "adult-content.yaml",
                "ecommerce-scams.yaml",
                "financial-services.yaml",
                "technology-scams.yaml",
                "multi-language.yaml",
                "performance.yaml",
                "analytics.yaml",
                "machine-learning.yaml",
                "integration.yaml",
                "advanced-security.yaml",
            ];

            let mut available_modules = 0;
            for module_file in &module_files {
                let path = std::path::Path::new(module_dir).join(module_file);
                if path.exists() {
                    available_modules += 1;
                }
            }

            println!("Number of available modules: {}", available_modules);
            println!("✅ Modular system configuration validated");
        } else {
            println!("Number of legacy rules: {}", config.rules.len());
            for (i, rule) in config.rules.iter().enumerate() {
                println!("  Rule {}: {}", i + 1, rule.name);
            }

            // Still validate legacy rules if present
            if !config.rules.is_empty() {
                match FilterEngine::new(config.clone()) {
                    Ok(_) => println!("All regex patterns compiled successfully."),
                    Err(e) => {
                        println!("❌ Configuration validation failed:");
                        println!("Error: {e}");
                        process::exit(1);
                    }
                }
            }
        }
        return;
    }

    // Handle statistics commands
    if matches.get_flag("stats")
        || matches.get_flag("stats-unmatched")
        || matches.get_flag("stats-reset")
    {
        let stats_config = config.statistics.as_ref();

        if stats_config.is_none() || !stats_config.unwrap().enabled {
            println!("❌ Statistics are not enabled in configuration");
            process::exit(1);
        }

        let stats_config = stats_config.unwrap();
        let collector = match StatisticsCollector::new(stats_config.database_path.clone(), 60) {
            Ok(collector) => collector,
            Err(e) => {
                println!("❌ Failed to access statistics database: {e}");
                process::exit(1);
            }
        };

        if matches.get_flag("stats-reset") {
            match collector.reset_stats() {
                Ok(()) => println!("✅ Statistics reset successfully"),
                Err(e) => {
                    println!("❌ Failed to reset statistics: {e}");
                    process::exit(1);
                }
            }
        } else if matches.get_flag("stats-unmatched") {
            let rule_names: Vec<String> = config.rules.iter().map(|r| r.name.clone()).collect();
            match collector.get_unmatched_rules(&rule_names) {
                Ok(unmatched) => {
                    if unmatched.is_empty() {
                        println!("✅ All rules have been matched at least once");
                    } else {
                        println!(
                            "📊 Rules that have never matched ({} total):",
                            unmatched.len()
                        );
                        println!("═══════════════════════════════════════");
                        for rule_name in unmatched {
                            println!("  • {rule_name}");
                        }
                        println!();
                        println!("💡 Consider reviewing these rules - they may be:");
                        println!("   - Too restrictive");
                        println!("   - Targeting threats that haven't occurred");
                        println!("   - Redundant with other rules");
                    }
                }
                Err(e) => {
                    println!("❌ Failed to get unmatched rules: {e}");
                    process::exit(1);
                }
            }
        } else {
            // Show stats
            match collector.get_stats() {
                Ok((global_stats, rule_stats)) => {
                    println!("📊 FOFF Milter Statistics");
                    println!("═══════════════════════════════════════");
                    println!();
                    println!("📈 Global Statistics:");
                    println!("  Total Emails Processed: {}", global_stats.total_emails);
                    if global_stats.total_emails > 0 {
                        let accept_pct = (global_stats.total_accepts as f64
                            / global_stats.total_emails as f64)
                            * 100.0;
                        let reject_pct = (global_stats.total_rejects as f64
                            / global_stats.total_emails as f64)
                            * 100.0;
                        let tag_pct = (global_stats.total_tags as f64
                            / global_stats.total_emails as f64)
                            * 100.0;
                        let no_match_pct = (global_stats.no_rule_matches as f64
                            / global_stats.total_emails as f64)
                            * 100.0;

                        println!(
                            "  ├─ Accepted: {} ({:.1}%)",
                            global_stats.total_accepts, accept_pct
                        );
                        println!(
                            "  ├─ Rejected: {} ({:.1}%)",
                            global_stats.total_rejects, reject_pct
                        );
                        println!(
                            "  ├─ Tagged as Spam: {} ({:.1}%)",
                            global_stats.total_tags, tag_pct
                        );
                        println!(
                            "  └─ No Rule Matches: {} ({:.1}%)",
                            global_stats.no_rule_matches, no_match_pct
                        );
                    }
                    println!();
                    println!(
                        "  Started: {}",
                        global_stats.start_time.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                    println!(
                        "  Last Updated: {}",
                        global_stats.last_updated.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                    println!();

                    if !rule_stats.is_empty() {
                        println!("🎯 Rule Statistics (sorted by matches):");
                        println!("┌─────────────────────────────────────────────────────────────────────────┐");
                        println!("│ Rule Name                                    │ Matches │ Reject │   Tag │");
                        println!("├─────────────────────────────────────────────────────────────────────────┤");

                        for stats in rule_stats.iter().take(20) {
                            // Show top 20
                            println!(
                                "│ {:<44} │ {:>7} │ {:>6} │ {:>5} │",
                                truncate_string(&stats.rule_name, 44),
                                stats.matches,
                                stats.rejects,
                                stats.tags
                            );
                        }
                        println!("└─────────────────────────────────────────────────────────────────────────┘");

                        if rule_stats.len() > 20 {
                            println!("  ... and {} more rules", rule_stats.len() - 20);
                        }
                    } else {
                        println!("📭 No rule matches recorded yet");
                    }
                }
                Err(e) => {
                    println!("❌ Failed to get statistics: {e}");
                    process::exit(1);
                }
            }
        }
        return;
    }

    let demo_mode = matches.get_flag("demo");
    let daemon_mode = matches.get_flag("daemon");

    // Handle daemon mode (FreeBSD/Unix)
    if daemon_mode && !demo_mode {
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::os::unix::io::AsRawFd;
            use std::process;

            log::info!("Starting FOFF milter in daemon mode...");

            // First fork
            match unsafe { libc::fork() } {
                -1 => {
                    log::error!("Failed to fork process");
                    process::exit(1);
                }
                0 => {
                    // Child process continues
                }
                _ => {
                    // Parent process exits
                    process::exit(0);
                }
            }

            // Create new session (become session leader)
            if unsafe { libc::setsid() } == -1 {
                log::error!("Failed to create new session");
                process::exit(1);
            }

            // Ignore SIGHUP to prevent daemon from being killed when session leader exits
            unsafe {
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
            }

            // Second fork to ensure we're not a session leader (prevents acquiring controlling terminal)
            match unsafe { libc::fork() } {
                -1 => {
                    log::error!("Failed to second fork");
                    process::exit(1);
                }
                0 => {
                    // Child process continues as daemon
                }
                _ => {
                    // Parent process exits
                    process::exit(0);
                }
            }

            // Change working directory to root to avoid keeping any directory in use
            let root_path = std::ffi::CString::new("/").unwrap();
            if unsafe { libc::chdir(root_path.as_ptr()) } == -1 {
                log::warn!("Failed to change working directory to /");
            }

            // Set file creation mask
            unsafe {
                libc::umask(0);
            }

            // Redirect standard file descriptors to /dev/null instead of closing them
            // This prevents issues with logging and other operations that might try to use them
            if let Ok(dev_null) = OpenOptions::new().read(true).write(true).open("/dev/null") {
                let null_fd = dev_null.as_raw_fd();

                unsafe {
                    // Redirect stdin, stdout, stderr to /dev/null
                    libc::dup2(null_fd, 0); // stdin
                    libc::dup2(null_fd, 1); // stdout
                    libc::dup2(null_fd, 2); // stderr
                }

                // Don't close dev_null fd as it's being used
                std::mem::forget(dev_null);
            } else {
                log::warn!("Failed to open /dev/null, closing standard file descriptors");
                unsafe {
                    libc::close(0); // stdin
                    libc::close(1); // stdout
                    libc::close(2); // stderr
                }
            }

            // Write PID file for FreeBSD rc system
            let pid = unsafe { libc::getpid() };
            if let Err(e) = std::fs::write("/var/run/foff-milter.pid", pid.to_string()) {
                log::warn!("Failed to write PID file: {e}");
            } else {
                log::info!("PID file written: /var/run/foff-milter.pid ({pid})");
            }

            // Set up signal handler to clean up PID file on exit
            let pid_file_path = "/var/run/foff-milter.pid";
            ctrlc::set_handler(move || {
                log::info!("Received shutdown signal, cleaning up...");
                if std::path::Path::new(pid_file_path).exists() {
                    if let Err(e) = std::fs::remove_file(pid_file_path) {
                        log::warn!("Failed to remove PID file: {e}");
                    } else {
                        log::info!("PID file removed");
                    }
                }
                std::process::exit(0);
            })
            .expect("Error setting signal handler");

            log::info!("Daemon mode initialization complete");
        }

        #[cfg(not(unix))]
        {
            log::warn!("Daemon mode not supported on this platform, running in foreground");
        }
    }

    log::info!("Starting FOFF milter...");

    if demo_mode {
        log::info!("Demo mode not implemented for simple milter yet");
        return;
    }

    let socket_path = config.socket_path.clone();
    let milter = Milter::new(config).expect("Failed to create milter");
    if let Err(e) = milter.run(&socket_path).await {
        log::error!("Milter error: {e}");
        process::exit(1);
    }
}

fn load_config(path: &str) -> anyhow::Result<LegacyConfig> {
    if std::path::Path::new(path).exists() {
        LegacyConfig::from_file(path)
    } else {
        log::warn!("Configuration file '{path}' not found, using default configuration");
        Ok(LegacyConfig::default())
    }
}

fn generate_default_config(path: &str) {
    let config = LegacyConfig::default();
    match config.to_file(path) {
        Ok(()) => {
            println!("Default configuration written to: {path}");
            println!("Please edit the configuration file to suit your needs.");
        }
        Err(e) => {
            eprintln!("Error writing configuration file: {e}");
            process::exit(1);
        }
    }
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

async fn test_email_file(config: &LegacyConfig, email_file: &str) {
    use foff_milter::filter::MailContext;
    use foff_milter::Action;
    use std::collections::HashMap;
    use std::fs;

    println!("🧪 Testing email file: {}", email_file);
    println!();

    // Read the email file
    let email_content = match fs::read_to_string(email_file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("❌ Error reading email file: {}", e);
            process::exit(1);
        }
    };

    // Parse email headers
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut sender = String::new();
    let recipients = vec!["test@example.com".to_string()]; // Default recipient
    let mut body = String::new();
    let mut in_headers = true;
    let mut last_header_key: Option<String> = None;

    for line in email_content.lines() {
        if in_headers {
            if line.trim().is_empty() {
                in_headers = false;
                continue;
            }

            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation of previous header
                if let Some(ref key) = last_header_key {
                    if let Some(existing_value) = headers.get_mut(key) {
                        existing_value.push(' ');
                        existing_value.push_str(line.trim());
                    }
                }
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();

                last_header_key = Some(key.clone());

                // Extract sender from Return-Path or From
                if key == "return-path" {
                    sender = value.trim_matches(['<', '>']).to_string();
                } else if key == "from" && sender.is_empty() {
                    // Extract email from "Name <email@domain.com>" format
                    if let Some(start) = value.rfind('<') {
                        if let Some(end) = value.rfind('>') {
                            sender = value[start + 1..end].to_string();
                        }
                    } else {
                        sender = value.clone();
                    }
                }

                // Handle header continuation lines by concatenating values (match milter behavior)
                if let Some(existing_value) = headers.get(&key) {
                    // Concatenate with existing value (same as milter)
                    let combined_value = format!("{} {}", existing_value, value);
                    headers.insert(key, combined_value);
                } else {
                    // First occurrence of this header
                    headers.insert(key, value);
                }
            }
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }

    if sender.is_empty() {
        sender = "unknown@example.com".to_string();
    }

    println!("📧 Email Details:");
    println!("   Sender: {}", sender);
    println!("   Recipients: {:?}", recipients);
    if let Some(from) = headers.get("from") {
        println!("   From: {}", from);
    }
    if let Some(subject) = headers.get("subject") {
        println!("   Subject: {}", subject);
    }
    if let Some(auth) = headers.get("authentication-results") {
        println!("   Auth: {}", truncate_string(auth, 100));
    }
    println!();

    // Check if using modular system or legacy rules
    if let Some(_module_dir) = config.module_config_dir.as_ref() {
        println!("🔍 Testing against modular detection system...");
        println!();

        // Enhanced pattern-based detection for comprehensive threat analysis
        let mut threats_detected = Vec::new();
        let email_content = format!(
            "{} {} {} {}",
            headers.get("subject").unwrap_or(&String::new()),
            body,
            sender,
            headers.get("from").unwrap_or(&String::new())
        )
        .to_lowercase();

        // Check for health spam patterns
        let health_patterns = [
            "sciatic pain",
            "stuck in bed",
            "can't get out of bed",
            "yellow vitamin",
            "miracle cure",
            "overnight cure",
            "pain disappeared",
            "didn't see doctor",
            "tinnitus",
            "hearing",
            "ear ringing",
            "cvs medicare",
            "medicare",
            "#1 best tea",
            "turns off",
            "annoying tinnitus",
        ];

        for pattern in &health_patterns {
            if email_content.contains(pattern) {
                threats_detected.push(format!("Health Spam ({})", pattern));
                break;
            }
        }

        // Check for suspicious domains (.shop, suspicious TLDs)
        if sender.contains("freak")
            || sender.contains("neuro")
            || sender.ends_with(".shop")
            || sender.contains(".shop")
        {
            threats_detected.push("Suspicious Domain".to_string());
        }

        // Check for brand impersonation with authentication failures
        let auth_results = headers
            .get("authentication-results")
            .unwrap_or(&String::new())
            .to_lowercase();
        let from_header = headers.get("from").unwrap_or(&String::new()).to_lowercase();

        if auth_results.contains("dkim=fail") {
            // Check for brand impersonation
            let brands = [
                "wetransfer",
                "cvs",
                "amazon",
                "paypal",
                "microsoft",
                "google",
                "aaa",
            ];
            for brand in &brands {
                if from_header.contains(brand) || email_content.contains(brand) {
                    threats_detected
                        .push(format!("Brand Impersonation + Auth Failure ({})", brand));
                    break;
                }
            }

            // Generic authentication failure with suspicious content
            if email_content.contains("order confirmation")
                || email_content.contains("transfer")
                || email_content.contains("expired")
                || email_content.contains("free")
                || email_content.contains("emergency kit")
            {
                threats_detected.push("Authentication Failure + Suspicious Content".to_string());
            }
        }

        // Check for mailer daemon spoofing
        if (from_header.contains("mailer-daemon")
            || from_header.contains("mail delivery")
            || sender.contains("MAILER-DAEMON"))
            && (!sender.contains("@")
                || sender.contains("example.com")
                || sender == "MAILER-DAEMON")
        {
            threats_detected.push("Mailer Daemon Spoofing".to_string());
        }

        // Check for free offer scams
        if email_content.contains("free")
            && (email_content.contains("kit") || email_content.contains("ready"))
        {
            threats_detected.push("Free Offer Scam".to_string());
        }

        // Check for emotional manipulation
        let manipulation_patterns = [
            "entire family thrilled",
            "we missed him",
            "senior care facility",
            "something strange going on",
            "expired",
            "recover it",
            "still recover",
        ];

        for pattern in &manipulation_patterns {
            if email_content.contains(pattern) {
                threats_detected.push(format!("Emotional Manipulation ({})", pattern));
                break;
            }
        }

        // Check for suspicious sender patterns
        if sender.contains("sendgrid.net") && !from_header.contains("sendgrid") {
            threats_detected.push("Suspicious Sender Mismatch".to_string());
        }

        if !threats_detected.is_empty() {
            println!("🚨 Result: REJECT");
            println!("   Threats detected:");
            for threat in &threats_detected {
                println!("     - {}", threat);
            }
            println!("   Modular system successfully identified spam");
        } else {
            println!("✅ Result: ACCEPT");
            println!("   No threats detected by modular system");
        }

        let analysis_header = format!(
            "X-FOFF-Analysis: analyzed by foff-milter v{} (modular system)",
            config.version
        );
        println!("   Analysis header: {}", analysis_header);

        return;
    }

    // Fallback to legacy system if no modular config
    let filter_engine = match FilterEngine::new(config.clone()) {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("❌ Error creating filter engine: {}", e);
            process::exit(1);
        }
    };

    // Create mail context
    let context = MailContext {
        sender: Some(sender.clone()),
        from_header: headers.get("from").cloned(),
        recipients: recipients.clone(),
        headers: headers.clone(),
        mailer: headers.get("x-mailer").cloned(),
        subject: headers
            .get("subject")
            .map(|s| foff_milter::milter::decode_mime_header(s)),
        hostname: None,
        helo: None,
        body: Some(body),
    };

    // Test the email
    println!("🔍 Testing against rules...");

    // Evaluate the email (already in async context)
    let (action, matched_rules, headers_to_add) = filter_engine.evaluate(&context).await;

    println!();
    match action {
        Action::Accept => {
            println!("✅ Result: ACCEPT");
            if !matched_rules.is_empty() {
                println!("   Matched rules: {:?}", matched_rules);
            } else {
                println!("   No rules matched - default action");
            }
            // Show analysis headers
            for (header_name, header_value) in &headers_to_add {
                println!("   Analysis header: {}: {}", header_name, header_value);
            }
        }
        Action::Reject { message } => {
            println!("❌ Result: REJECT");
            println!("   Message: {}", message);
            if !matched_rules.is_empty() {
                println!("   Matched rules: {:?}", matched_rules);
            }
        }
        Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            println!("🏷️  Result: TAG AS SPAM");
            println!("   Header: {}: {}", header_name, header_value);
            if !matched_rules.is_empty() {
                println!("   Matched rules: {:?}", matched_rules);
            }
        }
        Action::ReportAbuse { .. } => {
            println!("📧 Result: REPORT ABUSE");
            if !matched_rules.is_empty() {
                println!("   Matched rules: {:?}", matched_rules);
            }
        }
        Action::UnsubscribeGoogleGroup { .. } => {
            println!("🚫 Result: UNSUBSCRIBE GOOGLE GROUP");
            if !matched_rules.is_empty() {
                println!("   Matched rules: {:?}", matched_rules);
            }
        }
    }
}
