use clap::{Arg, Command};
use foff_milter::filter::FilterEngine;
use foff_milter::milter::Milter;
use foff_milter::statistics::StatisticsCollector;
use foff_milter::Config;
use log::LevelFilter;
use std::process;

#[tokio::main]
async fn main() {
    let matches = Command::new("foff-milter")
        .version("0.1.0")
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

    if matches.get_flag("test-config") {
        println!("🔍 Testing configuration...");
        println!();

        // Try to create FilterEngine to validate all regex patterns
        match FilterEngine::new(config.clone()) {
            Ok(_) => {
                println!("✅ Configuration is valid!");
                println!("Socket path: {}", config.socket_path);
                println!("Number of rules: {}", config.rules.len());
                for (i, rule) in config.rules.iter().enumerate() {
                    println!("  Rule {}: {}", i + 1, rule.name);
                }
                println!();
                println!("All regex patterns compiled successfully.");
            }
            Err(e) => {
                println!("❌ Configuration validation failed:");
                println!("Error: {e}");
                process::exit(1);
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
                        println!("│ Rule Name                                    │ Matches │ Reject │  Tag │");
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

fn load_config(path: &str) -> anyhow::Result<Config> {
    if std::path::Path::new(path).exists() {
        Config::from_file(path)
    } else {
        log::warn!("Configuration file '{path}' not found, using default configuration");
        Ok(Config::default())
    }
}

fn generate_default_config(path: &str) {
    let config = Config::default();
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
