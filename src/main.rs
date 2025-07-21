use clap::{Arg, Command};
use foff_milter::{run_milter, Config};
use log::LevelFilter;
use std::process;

fn main() {
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
                .help("Test the configuration file and exit")
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
            eprintln!("Error loading configuration: {}", e);
            process::exit(1);
        }
    };

    if matches.get_flag("test-config") {
        println!("Configuration file is valid!");
        println!("Socket path: {}", config.socket_path);
        println!("Number of rules: {}", config.rules.len());
        for (i, rule) in config.rules.iter().enumerate() {
            println!("  Rule {}: {}", i + 1, rule.name);
        }
        return;
    }

    let demo_mode = matches.get_flag("demo");
    let daemon_mode = matches.get_flag("daemon");

    // Handle daemon mode (FreeBSD/Unix)
    if daemon_mode && !demo_mode {
        #[cfg(unix)]
        {
            use std::process;

            log::info!("Starting FOFF milter in daemon mode...");

            // Fork the process
            match unsafe { libc::fork() } {
                -1 => {
                    log::error!("Failed to fork process");
                    process::exit(1);
                }
                0 => {
                    // Child process - continue as daemon
                    // Create new session
                    if unsafe { libc::setsid() } == -1 {
                        log::error!("Failed to create new session");
                        process::exit(1);
                    }

                    // Change working directory to root
                    if unsafe { libc::chdir(c"/".as_ptr()) } == -1 {
                        log::warn!("Failed to change working directory to /");
                    }

                    // Close standard file descriptors
                    unsafe {
                        libc::close(0); // stdin
                        libc::close(1); // stdout
                        libc::close(2); // stderr
                    }
                }
                _ => {
                    // Parent process - exit
                    process::exit(0);
                }
            }
        }

        #[cfg(not(unix))]
        {
            log::warn!("Daemon mode not supported on this platform, running in foreground");
        }
    }

    log::info!("Starting FOFF milter...");

    if let Err(e) = run_milter(config, demo_mode) {
        log::error!("Milter error: {}", e);
        process::exit(1);
    }
}

fn load_config(path: &str) -> anyhow::Result<Config> {
    if std::path::Path::new(path).exists() {
        Config::from_file(path)
    } else {
        log::warn!(
            "Configuration file '{}' not found, using default configuration",
            path
        );
        Ok(Config::default())
    }
}

fn generate_default_config(path: &str) {
    let config = Config::default();
    match config.to_file(path) {
        Ok(()) => {
            println!("Default configuration written to: {}", path);
            println!("Please edit the configuration file to suit your needs.");
        }
        Err(e) => {
            eprintln!("Error writing configuration file: {}", e);
            process::exit(1);
        }
    }
}
