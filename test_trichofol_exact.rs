use foff_milter::config::Config;
use foff_milter::filter::FilterEngine;
use foff_milter::milter::{MailContext, MilterConnection};

fn main() {
    env_logger::init();
    
    // Load the exact config
    let config = Config::from_file("test-trichofol-exact.yaml").unwrap();
    let mut engine = FilterEngine::new();
    engine.load_config(&config).unwrap();
    
    // Create a milter connection and simulate the exact email
    let mut milter = MilterConnection::new(engine);
    
    println!("=== Testing Exact Trichofol Email ===");
    
    // Simulate the exact email processing
    milter.process_connection("pines.trichofol.ru.com");
    milter.process_mail_from("97148-203879-10156-21091-mjohnson=example.com@mail.trichofol.ru.com");
    milter.process_rcpt_to("mjohnson@example.com");
    milter.process_header("From", "\"Carol\" <Nellie@trichofol.ru.com>");
    milter.process_header("Reply-To", "\"Melissa\" <Carolyn@trichofol.ru.com>");
    milter.process_header("Subject", "My cleaning techniques could be the cause of my daughter's sickness");
    milter.process_header("Message-ID", "<82runwew9gq5jai0-g0qjwysozj7qxnf4-31c67-27ac@trichofol.ru.com>");
    
    // Evaluate
    let action = milter.evaluate_message();
    println!("Action: {:?}", action);
    
    match action {
        foff_milter::config::Action::TagAsSpam { header_name, header_value } => {
            println!("✅ SUCCESS: Would tag with {}: {}", header_name, header_value);
        }
        foff_milter::config::Action::Reject { message } => {
            println!("❌ UNEXPECTED: Would reject with: {}", message);
        }
        foff_milter::config::Action::Accept => {
            println!("❌ FAILED: Email was accepted (not tagged)");
        }
    }
}
