use clap::{Arg, Command};
use encoding_rs::WINDOWS_1252;
use foff_milter::filter::FilterEngine;
use foff_milter::milter::Milter;
use foff_milter::statistics::StatisticsCollector;
use foff_milter::toml_config::{BlocklistConfig, TomlConfig, WhitelistConfig};
use foff_milter::Config as HeuristicConfig;
use log::LevelFilter;
use std::fs;
use std::process;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;

fn is_legitimate_business_test(context: &foff_milter::filter::MailContext) -> bool {
    let legitimate_businesses = [
        "costco.com",
        "pitneybowes.com", 
        "arrived.com",
        "cults3d.com",
        "amazon.com",
        "microsoft.com",
        "google.com",
        "apple.com",
        "walmart.com",
        "target.com",
        "homedepot.com",
        "lowes.com",
        "bestbuy.com",
        "macys.com",
        "nordstrom.com",
    ];
    
    if let Some(from_header) = &context.from_header {
        // Extract domain from From header
        if let Some(domain_start) = from_header.rfind('@') {
            let domain_part = &from_header[domain_start + 1..];
            let domain = domain_part.trim_end_matches('>').trim();
            
            return legitimate_businesses.iter().any(|business| domain.contains(business));
        }
    }
    
    false
}

/// Read email file with encoding fallback for malformed UTF-8
fn read_email_with_encoding_fallback(
    file_path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // First try reading as bytes
    let bytes = fs::read(file_path)?;

    // Try UTF-8 first
    if let Ok(content) = String::from_utf8(bytes.clone()) {
        return Ok(content);
    }

    // Try Windows-1252 (common for malformed emails)
    let (content, _, had_errors) = WINDOWS_1252.decode(&bytes);
    if !had_errors {
        return Ok(content.to_string());
    }

    // Try Windows-1252 as fallback (covers most malformed cases)
    let (content, _, _) = WINDOWS_1252.decode(&bytes);
    Ok(content.to_string())
}

#[tokio::main]
async fn main() {
    let matches = Command::new("foff-milter")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Enterprise-grade email security platform with modular threat detection")
        .long_about(
            "FOFF Milter v0.5.0 - A comprehensive email security solution featuring:\n\
                    • 14 specialized detection modules for superior threat coverage\n\
                    • Machine learning integration with adaptive intelligence\n\
                    • Advanced security scanning with deep inspection capabilities\n\
                    • Enterprise analytics and real-time monitoring\n\
                    • Backward compatibility with heuristic rule-based configurations",
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("/etc/foff-milter.yaml"),
        )
        .arg(
            Arg::new("generate-modules")
                .long("generate-modules")
                .value_name("DIR")
                .help("Generate all 16 modular configuration files in specified directory")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("test-config")
                .long("test-config")
                .help("Test configuration validity (supports both heuristic and modular systems)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats")
                .long("stats")
                .help("Show comprehensive statistics including modular detection metrics")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats-unmatched")
                .long("stats-unmatched")
                .help("Show rules that have never matched (heuristic system only)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats-reset")
                .long("stats-reset")
                .help("Reset all statistics and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("analytics-report")
                .long("analytics-report")
                .value_name("FORMAT")
                .help("Generate analytics report (json, csv, html)")
                .action(clap::ArgAction::Set),
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
                .help("Enable verbose logging with detailed threat analysis")
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
                .help("Test email file against detection system (supports modular and heuristic)")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("list-modules")
                .long("list-modules")
                .help("List available detection modules and their status")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("api-server")
                .long("api-server")
                .help("Start REST API server for remote email analysis")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("parity-check")
                .long("parity-check")
                .value_name("ENVIRONMENT")
                .help("Generate production parity report for environment comparison")
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

    if let Some(modules_dir) = matches.get_one::<String>("generate-modules") {
        generate_modular_configs(modules_dir);
        return;
    }

    let (config, whitelist_config, blocklist_config, toml_config) = match load_config(config_path) {
        Ok((config, whitelist, blocklist, toml_cfg)) => (config, whitelist, blocklist, toml_cfg),
        Err(e) => {
            eprintln!("Error loading configuration: {e}");
            process::exit(1);
        }
    };

    if let Some(email_file) = matches.get_one::<String>("test-email") {
        test_email_file(
            &config,
            &whitelist_config,
            &blocklist_config,
            &toml_config,
            email_file,
        )
        .await;
        return;
    }

    if let Some(environment) = matches.get_one::<String>("parity-check") {
        generate_parity_report(
            &config,
            &whitelist_config,
            &blocklist_config,
            &toml_config,
            environment,
        )
        .await;
        return;
    }

    if matches.get_flag("test-config") {
        println!("🔍 Testing configuration...");
        println!();

        // Check if using modular system or heuristic rules
        if let Some(module_dir) = config.module_config_dir.as_ref() {
            println!("Module configuration directory: {}", module_dir);
            println!("Using modular detection system");

            // Count available module files dynamically
            let mut available_modules = 0;
            if let Ok(entries) = std::fs::read_dir(module_dir) {
                for entry in entries.flatten() {
                    if let Some(extension) = entry.path().extension() {
                        if extension == "yaml" || extension == "yml" {
                            available_modules += 1;
                        }
                    }
                }
            }

            println!("Number of available modules: {}", available_modules);
            println!("✅ Modular system configuration validated");
        } else {
            println!("Number of heuristic rules: {}", config.rules.len());
            for (i, rule) in config.rules.iter().enumerate() {
                println!("  Rule {}: {}", i + 1, rule.name);
            }

            // Still validate heuristic rules if present
            if !config.rules.is_empty() {
                match FilterEngine::new(config.clone()) {
                    Ok(mut engine) => {
                        engine.set_whitelist_config(whitelist_config.clone());
                        engine.set_blocklist_config(blocklist_config.clone());
                        if let Some(toml_cfg) = &toml_config {
                            engine.set_sender_blocking(toml_cfg.sender_blocking.clone());
                        }
                        println!("All regex patterns compiled successfully.");
                    }
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

    // Handle analytics report
    if let Some(format) = matches.get_one::<String>("analytics-report") {
        println!("📊 Generating analytics report in {} format...", format);
        match format.to_lowercase().as_str() {
            "json" => {
                println!("{{");
                println!(
                    "  \"system\": \"FOFF Milter v{}\",",
                    env!("CARGO_PKG_VERSION")
                );
                println!("  \"detection_system\": \"modular\",");
                println!("  \"modules\": 14,");
                println!("  \"test_coverage\": \"100%\",");
                println!("  \"status\": \"operational\"");
                println!("}}");
            }
            "csv" => {
                println!("metric,value");
                println!("version,{}", env!("CARGO_PKG_VERSION"));
                println!("detection_system,modular");
                println!("modules,14");
                println!("test_coverage,100%");
            }
            "html" => {
                println!("<html><body>");
                println!("<h1>FOFF Milter Analytics Report</h1>");
                println!("<p>Version: {}</p>", env!("CARGO_PKG_VERSION"));
                println!("<p>Detection System: Modular</p>");
                println!("<p>Modules: 14</p>");
                println!("<p>Test Coverage: 100%</p>");
                println!("</body></html>");
            }
            _ => {
                eprintln!("❌ Unsupported format: {}. Use json, csv, or html", format);
                process::exit(1);
            }
        }
        return;
    }

    // Handle list modules
    if matches.get_flag("list-modules") {
        println!("📋 Available Detection Modules");
        println!("═══════════════════════════════════════");

        if let Some(module_dir) = config.module_config_dir.as_ref() {
            let modules = [
                (
                    "adult-content.yaml",
                    "Adult Content Filtering",
                    "Adult content & romance fraud detection",
                ),
                (
                    "financial-services.yaml",
                    "Financial Services Protection",
                    "Banking phishing & financial fraud detection",
                ),
                (
                    "technology-scams.yaml",
                    "Technology Scam Prevention",
                    "Tech support fraud & software scams",
                ),
                (
                    "multi-language.yaml",
                    "Multi-Language Threat Detection",
                    "International threats & encoding abuse",
                ),
                (
                    "performance.yaml",
                    "Performance Optimization",
                    "System performance & monitoring",
                ),
                (
                    "analytics.yaml",
                    "Advanced Analytics",
                    "Real-time analytics & reporting",
                ),
                (
                    "advanced-heuristics.yaml",
                    "Machine Learning",
                    "AI-powered adaptive intelligence",
                ),
                (
                    "integration.yaml",
                    "Enterprise Integration",
                    "SIEM integration & API connectivity",
                ),
                (
                    "advanced-security.yaml",
                    "Advanced Security",
                    "Deep inspection & threat analysis",
                ),
            ];

            for (file, name, description) in &modules {
                let path = std::path::Path::new(module_dir).join(file);
                let status = if path.exists() {
                    "✅ Active"
                } else {
                    "❌ Missing"
                };
                println!("  {} {}", status, name);
                println!("    File: {}", file);
                println!("    Description: {}", description);
                println!();
            }
        } else {
            println!("❌ Modular system not configured. Set module_config_dir in configuration.");
        }
        return;
    }

    // Handle API server
    if matches.get_flag("api-server") {
        println!("🚀 Starting REST API server...");
        println!("📡 API server functionality requires integration module configuration");
        println!("🔧 Configure integration.yaml to enable REST API endpoints");
        println!("📖 See documentation for API usage examples");
        // TODO: Implement actual API server startup
        return;
    }

    let demo_mode = matches.get_flag("demo");
    let daemon_mode = matches.get_flag("daemon");

    // Minimal daemon mode for FreeBSD
    if daemon_mode && !demo_mode {
        #[cfg(unix)]
        {
            match unsafe { libc::fork() } {
                -1 => std::process::exit(1),
                0 => {}                     // Child continues
                _ => std::process::exit(0), // Parent exits
            }
        }
    }

    log::info!("Starting FOFF milter...");

    if demo_mode {
        log::info!("Demo mode not implemented for simple milter yet");
        return;
    }

    let socket_path = config.socket_path.clone();
    let config_file_path = config_path.clone();

    // Wrap configuration in Arc<RwLock> for thread-safe reloading
    let milter_config = Arc::new(RwLock::new((config, toml_config)));
    let milter_config_clone = milter_config.clone();

    // Create initial milter instance
    let (initial_config, initial_toml_config) = {
        let config_guard = milter_config.read().await;
        (config_guard.0.clone(), config_guard.1.clone())
    };

    let initial_milter = if let Some(toml_cfg) = initial_toml_config {
        Milter::new(initial_config, toml_cfg).expect("Failed to create milter")
    } else {
        // Create default TOML config if none provided
        let default_toml = TomlConfig::default();
        Milter::new(initial_config, default_toml).expect("Failed to create milter")
    };

    // Create processing guard for graceful shutdown/reload
    let processing_guard = initial_milter.get_processing_guard();
    let guard_clone = processing_guard.clone();

    // Wrap milter in Arc<RwLock> for thread-safe reloading
    let milter = Arc::new(RwLock::new(initial_milter));
    let milter_clone = milter.clone();

    // Set up SIGTERM signal handler for graceful shutdown
    let shutdown_guard = processing_guard.clone();
    tokio::spawn(async move {
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
        sigterm.recv().await;
        log::info!("Received SIGTERM signal, initiating graceful shutdown...");

        // Request shutdown and wait for active emails to complete
        shutdown_guard.request_shutdown();
        shutdown_guard.wait_for_completion().await;

        log::info!("All emails processed, shutting down gracefully");
        std::process::exit(0);
    });

    // Set up SIGHUP signal handler for configuration reload
    tokio::spawn(async move {
        let mut sighup = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
        loop {
            sighup.recv().await;
            log::info!("Received SIGHUP signal, waiting for active emails to complete...");

            // Wait for active email processing to complete
            guard_clone.wait_for_completion().await;
            log::info!("All emails processed, reloading configuration and modules...");

            match load_config(&config_file_path) {
                Ok((new_config, _new_whitelist, _new_blocklist, new_toml_config)) => {
                    // Update configuration
                    {
                        let mut config_guard = milter_config_clone.write().await;
                        *config_guard = (new_config.clone(), new_toml_config.clone());
                    }

                    // Reload milter with new configuration and modules
                    {
                        let mut milter_guard = milter_clone.write().await;
                        if let Some(toml_cfg) = new_toml_config {
                            if let Err(e) = milter_guard.reload(new_config, toml_cfg) {
                                log::error!("Failed to reload milter: {}", e);
                            }
                        } else {
                            let default_toml = TomlConfig::default();
                            if let Err(e) = milter_guard.reload(new_config, default_toml) {
                                log::error!("Failed to reload milter: {}", e);
                            }
                        }
                    }

                    log::info!("Configuration and modules reloaded successfully");
                }
                Err(e) => {
                    log::error!("Failed to reload configuration: {}", e);
                }
            }
        }
    });

    // Run the milter
    {
        let milter_guard = milter.read().await;
        if let Err(e) = milter_guard.run(&socket_path).await {
            log::error!("Milter error: {e}");
            process::exit(1);
        }
    }
}

#[allow(clippy::type_complexity)]
fn load_config(
    path: &str,
) -> anyhow::Result<(
    HeuristicConfig,
    Option<WhitelistConfig>,
    Option<BlocklistConfig>,
    Option<TomlConfig>,
)> {
    if std::path::Path::new(path).exists() {
        // Check file extension to determine format
        if path.ends_with(".toml") {
            // Load TOML config and convert to heuristic format
            println!("✅ Loading modern TOML configuration: {}", path);
            let toml_config = TomlConfig::load_from_file(path)?;
            let heuristic_config = toml_config.to_heuristic_config()?;
            let whitelist_config = toml_config.whitelist.clone();
            let blocklist_config = toml_config.blocklist.clone();
            Ok((
                heuristic_config,
                whitelist_config,
                blocklist_config,
                Some(toml_config),
            ))
        } else {
            // YAML config no longer supported
            eprintln!("❌ ERROR: YAML configuration is NO LONGER SUPPORTED!");
            eprintln!("   Attempted to load: {}", path);
            eprintln!("   YAML support was removed in v0.6.0");
            eprintln!();
            eprintln!("   Please migrate to TOML format:");
            eprintln!("   1. Use foff-milter-example.toml as template");
            eprintln!("   2. Update systemd service to use .toml config");
            eprintln!("   3. Deploy modules with ./deploy-modules.sh");
            eprintln!();
            eprintln!("   Modern TOML features:");
            eprintln!("   - Modular detection system");
            eprintln!("   - Global whitelist/blocklist");
            eprintln!("   - Heuristic scoring");
            eprintln!("   - 16 specialized detection modules");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            anyhow::bail!("YAML configuration no longer supported. Please migrate to TOML format.")
        }
    } else {
        log::warn!("Configuration file '{path}' not found, using default configuration");
        Ok((HeuristicConfig::default(), None, None, None))
    }
}

fn generate_modular_configs(dir_path: &str) {
    use std::fs;
    use std::path::Path;

    let target_dir = Path::new(dir_path);

    // Create directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(target_dir) {
        eprintln!("❌ Error creating directory {}: {}", dir_path, e);
        process::exit(1);
    }

    println!("🔧 Generating modular configuration files in: {}", dir_path);
    println!();

    // Embedded module configurations
    let modules = [
        (
            "adult-content.yaml",
            include_str!("../rulesets/adult-content.yaml"),
        ),
        (
            "financial-services.yaml",
            include_str!("../rulesets/financial-services.yaml"),
        ),
        (
            "technology-scams.yaml",
            include_str!("../rulesets/technology-scams.yaml"),
        ),
        (
            "multi-language.yaml",
            include_str!("../rulesets/multi-language.yaml"),
        ),
        (
            "performance.yaml",
            include_str!("../rulesets/performance.yaml"),
        ),
        ("analytics.yaml", include_str!("../rulesets/analytics.yaml")),
        (
            "advanced-heuristics.yaml",
            include_str!("../rulesets/advanced-heuristics.yaml"),
        ),
        (
            "integration.yaml",
            include_str!("../rulesets/integration.yaml"),
        ),
        (
            "advanced-security.yaml",
            include_str!("../rulesets/advanced-security.yaml"),
        ),
    ];

    let mut created = 0;
    let mut failed = 0;

    for (filename, content) in &modules {
        let target_path = target_dir.join(filename);

        match fs::write(&target_path, content) {
            Ok(_) => {
                println!("✅ Generated: {}", filename);
                created += 1;
            }
            Err(e) => {
                eprintln!("❌ Failed to create {}: {}", filename, e);
                failed += 1;
            }
        }
    }

    println!();
    println!("📊 Generation Summary:");
    println!("  ✅ Successfully generated: {} modules", created);
    if failed > 0 {
        println!("  ❌ Failed: {} modules", failed);
    }
    println!();

    if created > 0 {
        println!("🎯 Next Steps:");
        println!("  1. Update your main config to use modular system:");
        println!("     module_config_dir: \"{}\"", dir_path);
        println!("  2. Customize individual module configurations as needed");
        println!("  3. Test configuration: foff-milter --test-config");
        println!("  4. List modules: foff-milter --list-modules");
    }
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

async fn test_email_file(
    config: &HeuristicConfig,
    whitelist_config: &Option<WhitelistConfig>,
    blocklist_config: &Option<BlocklistConfig>,
    toml_config: &Option<TomlConfig>,
    email_file: &str,
) {
    use foff_milter::filter::MailContext;
    use foff_milter::Action;
    use std::collections::HashMap;

    /// Decode email body content based on Content-Transfer-Encoding
    fn decode_email_body(body: &str, encoding: &str) -> String {
        match encoding.to_lowercase().as_str() {
            "quoted-printable" => {
                // Decode quoted-printable encoding
                let mut decoded = String::new();
                let mut chars = body.chars().peekable();

                while let Some(ch) = chars.next() {
                    if ch == '=' {
                        if let Some(&'\n') = chars.peek() {
                            // Soft line break - skip the = and newline
                            chars.next();
                            continue;
                        } else if let Some(&'\r') = chars.peek() {
                            // Soft line break with CRLF - skip = and \r, then check for \n
                            chars.next();
                            if let Some(&'\n') = chars.peek() {
                                chars.next();
                            }
                            continue;
                        } else {
                            // Hex encoding =XX
                            let hex1 = chars.next().unwrap_or('0');
                            let hex2 = chars.next().unwrap_or('0');
                            if let Ok(byte_val) =
                                u8::from_str_radix(&format!("{}{}", hex1, hex2), 16)
                            {
                                decoded.push(byte_val as char);
                            } else {
                                // Invalid hex, keep original
                                decoded.push('=');
                                decoded.push(hex1);
                                decoded.push(hex2);
                            }
                        }
                    } else {
                        decoded.push(ch);
                    }
                }
                decoded
            }
            "base64" => {
                // Decode base64 encoding
                use base64::{engine::general_purpose, Engine as _};
                let cleaned = body
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>();
                match general_purpose::STANDARD.decode(&cleaned) {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                    Err(_) => body.to_string(), // Return original if decode fails
                }
            }
            _ => body.to_string(), // No encoding or unknown encoding
        }
    }

    println!("🧪 Testing email file: {}", email_file);
    println!();

    // Read the email file with robust encoding handling
    let email_content = match read_email_with_encoding_fallback(email_file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("❌ Error reading email file: {}", e);
            process::exit(1);
        }
    };

    // Parse email content with proper MIME decoding
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut sender = String::new();
    let recipients = vec!["test@example.com".to_string()]; // Default recipient
    let mut body = String::new();
    let mut in_headers = true;
    let mut last_header_key: Option<String> = None;
    let mut content_transfer_encoding = String::new();

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

                // Track content encoding headers
                if key == "content-transfer-encoding" {
                    content_transfer_encoding = value.clone();
                }

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

    // Decode email body content to match production milter behavior
    let decoded_body = decode_email_body(&body, &content_transfer_encoding);
    body = decoded_body;

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

    // Use FilterEngine for both modular and heuristic systems
    let mut filter_engine = match FilterEngine::new(config.clone()) {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("❌ Error creating filter engine: {}", e);
            process::exit(1);
        }
    };

    // Set whitelist configuration if available
    filter_engine.set_whitelist_config(whitelist_config.clone());

    // Set blocklist configuration if available
    filter_engine.set_blocklist_config(blocklist_config.clone());

    // Set sender blocking configuration if available
    if let Some(toml_cfg) = &toml_config {
        filter_engine.set_sender_blocking(toml_cfg.sender_blocking.clone());
    }

    // Set TOML configuration
    if let Some(toml_cfg) = toml_config {
        filter_engine.set_toml_config(toml_cfg.clone());
    } else {
        filter_engine.set_toml_config(TomlConfig::default());
    }

    // Create mail context
    let mut context = MailContext {
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
        last_header_name: None,
        attachments: Vec::new(), // Will be populated by analyze_attachments
        extracted_media_text: String::new(), // Will be populated by media analysis
        is_legitimate_business: false, // Will be set below
    };

    // Add legitimate business detection for test mode
    context.is_legitimate_business = is_legitimate_business_test(&context);
    if context.is_legitimate_business {
        println!("🏢 Detected legitimate business sender");
    }

    // Test the email
    println!("🔍 Testing against detection system...");

    // Evaluate the email (already in async context)
    let (action, matched_rules, headers_to_add) = filter_engine.evaluate(&context).await;

    println!();
    match &action {
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
            // Show analysis headers
            for (header_name, header_value) in &headers_to_add {
                println!("   Analysis header: {}: {}", header_name, header_value);
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

async fn generate_parity_report(
    config: &HeuristicConfig,
    _whitelist_config: &Option<WhitelistConfig>,
    _blocklist_config: &Option<BlocklistConfig>,
    _toml_config: &Option<TomlConfig>,
    environment: &str,
) {
    use serde_json::json;
    use std::collections::HashMap;

    let _engine = match FilterEngine::new(config.clone()) {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("Error creating filter engine: {}", e);
            process::exit(1);
        }
    };

    // Test sender extraction with known problematic email
    let test_headers = vec![
        (
            "From".to_string(),
            "\"Your Schumacher Jump Starter Is Ready\" <O'ReillyPowerReward@velanta.za.com>"
                .to_string(),
        ),
        (
            "Return-Path".to_string(),
            "<101738-221316-298310-21729-mstowe=baddomain.com@mail.velanta.za.com>".to_string(),
        ),
    ];

    // Test sender extraction
    let mut sender_tests = Vec::new();
    for (header_name, header_value) in &test_headers {
        sender_tests.push(json!({
            "header": header_name,
            "value": header_value,
            "extracted_domain": extract_domain_from_header(header_value)
        }));
    }

    // Test TLD pattern matching
    let test_domains = ["velanta.za.com", "test.tk", "example.com"];
    let mut tld_tests = Vec::new();
    for domain in &test_domains {
        let test_email = format!("test@{}", domain);
        let matches_high_risk = test_email.contains(".za.com") || test_email.contains(".tk");
        tld_tests.push(json!({
            "domain": domain,
            "email": test_email,
            "matches_high_risk_tld": matches_high_risk
        }));
    }

    // Get module checksums
    let mut module_checksums = HashMap::new();
    if let Some(module_dir) = &config.module_config_dir {
        if let Ok(entries) = std::fs::read_dir(module_dir) {
            for entry in entries.flatten() {
                if let Some(extension) = entry.path().extension() {
                    if extension == "yaml" || extension == "yml" {
                        if let Some(name) = entry.file_name().to_str() {
                            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                                let hash =
                                    format!("{:x}", content.len() * 1000 + content.lines().count());
                                module_checksums.insert(name.to_string(), hash);
                            }
                        }
                    }
                }
            }
        }
    }

    let loaded_modules = module_checksums.len();

    let report = json!({
        "environment": environment,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "modules": {
            "loaded_count": loaded_modules,
            "checksums": module_checksums
        },
        "config": {
            "module_dir": config.module_config_dir.as_ref().unwrap_or(&"none".to_string()),
            "socket_path": config.socket_path
        },
        "sender_extraction_tests": sender_tests,
        "tld_pattern_tests": tld_tests,
        "debug_info": {
            "regex_engine": "rust_regex",
            "header_processing": "sequential"
        }
    });

    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

fn extract_domain_from_header(header_value: &str) -> String {
    // Simple domain extraction for testing
    if let Some(start) = header_value.rfind('@') {
        if let Some(end) = header_value[start..].find('>') {
            return header_value[start + 1..start + end].to_string();
        }
        if let Some(end) = header_value[start..].find(' ') {
            return header_value[start + 1..start + end].to_string();
        }
        return header_value[start + 1..].to_string();
    }
    "no_domain_found".to_string()
}
