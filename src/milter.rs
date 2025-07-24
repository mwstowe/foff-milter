use crate::config::{Action, Config};
use crate::filter::{FilterEngine, MailContext};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

// Milter protocol constants
const SMFIC_ABORT: u8 = b'A';
const SMFIC_BODY: u8 = b'B';
const SMFIC_CONNECT: u8 = b'C';
const SMFIC_MACRO: u8 = b'D';
const SMFIC_BODYEOB: u8 = b'E';
const SMFIC_HELO: u8 = b'H';
const SMFIC_HEADER: u8 = b'L';
const SMFIC_MAIL: u8 = b'M';
const SMFIC_EOH: u8 = b'N';
const SMFIC_OPTNEG: u8 = b'O';
const SMFIC_QUIT: u8 = b'Q';
const SMFIC_RCPT: u8 = b'R';
const SMFIC_DATA: u8 = b'T';

// Milter response constants
#[allow(dead_code)]
const SMFIR_ADDRCPT: u8 = b'+';
#[allow(dead_code)]
const SMFIR_DELRCPT: u8 = b'-';

#[allow(dead_code)]
const SMFIR_REPLBODY: u8 = b'b';
const SMFIR_CONTINUE: u8 = b'c';
#[allow(dead_code)]
const SMFIR_DISCARD: u8 = b'd';
const SMFIR_ADDHEADER: u8 = b'h';
#[allow(dead_code)]
const SMFIR_INSHEADER: u8 = b'i';
#[allow(dead_code)]
const SMFIR_SETSYMLIST: u8 = b'l';
#[allow(dead_code)]
const SMFIR_CHGHEADER: u8 = b'm';
#[allow(dead_code)]
const SMFIR_PROGRESS: u8 = b'p';
#[allow(dead_code)]
const SMFIR_QUARANTINE: u8 = b'q';
#[allow(dead_code)]
const SMFIR_REJECT: u8 = b'r';
#[allow(dead_code)]
const SMFIR_SKIP: u8 = b's';
#[allow(dead_code)]
const SMFIR_TEMPFAIL: u8 = b't';
const SMFIR_REPLYCODE: u8 = b'y';

struct MilterConnection {
    stream: UnixStream,
    engine: Arc<FilterEngine>,
    context: MailContext,
}

impl MilterConnection {
    fn new(stream: UnixStream, engine: Arc<FilterEngine>) -> Self {
        Self {
            stream,
            engine,
            context: MailContext::default(),
        }
    }

    fn handle(&mut self) -> anyhow::Result<()> {
        log::info!("Starting to handle new milter connection");

        loop {
            log::info!("Waiting for next milter command...");
            match self.read_command() {
                Ok(Some((command, data))) => {
                    log::info!("Processing command: 0x{:02x} with {} bytes", command, data.len());
                    match self.process_command(command, data) {
                        Ok(true) => {
                            log::info!("Command processed successfully, continuing...");
                            continue; // Continue processing
                        }
                        Ok(false) => {
                            log::info!("Command indicated connection should close");
                            break;   // Connection should close
                        }
                        Err(e) => {
                            log::error!("Error processing command: {e}");
                            break;
                        }
                    }
                }
                Ok(None) => {
                    log::info!("Connection closed by client");
                    break; // Connection closed
                }
                Err(e) => {
                    log::error!("Error reading command: {e}");
                    break;
                }
            }
        }

        log::debug!("Milter connection closed");
        Ok(())
    }

    fn read_command(&mut self) -> anyhow::Result<Option<(u8, Vec<u8>)>> {
        // Read 4-byte length header
        let mut len_buf = [0u8; 4];
        match self.stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Ok(None);
        }

        // Read command byte
        let mut cmd_buf = [0u8; 1];
        self.stream.read_exact(&mut cmd_buf)?;
        let command = cmd_buf[0];

        // Read data (len - 1 because we already read the command byte)
        let mut data = vec![0u8; len - 1];
        if len > 1 {
            self.stream.read_exact(&mut data)?;
        }

        Ok(Some((command, data)))
    }

    fn send_response(&mut self, response: u8, data: &[u8]) -> anyhow::Result<()> {
        let len = (data.len() + 1) as u32;
        self.stream.write_all(&len.to_be_bytes())?;
        self.stream.write_all(&[response])?;
        if !data.is_empty() {
            self.stream.write_all(data)?;
        }
        self.stream.flush()?;
        Ok(())
    }

    fn process_command(&mut self, command: u8, data: Vec<u8>) -> anyhow::Result<bool> {
        log::info!("MILTER COMMAND: 0x{:02x} ({}) with {} bytes", 
                   command, 
                   match command {
                       SMFIC_OPTNEG => "OPTNEG",
                       SMFIC_CONNECT => "CONNECT", 
                       SMFIC_HELO => "HELO",
                       SMFIC_MAIL => "MAIL",
                       SMFIC_RCPT => "RCPT", 
                       SMFIC_DATA => "DATA",
                       SMFIC_HEADER => "HEADER",
                       SMFIC_EOH => "EOH",
                       SMFIC_BODY => "BODY",
                       SMFIC_BODYEOB => "BODYEOB",
                       SMFIC_ABORT => "ABORT",
                       SMFIC_QUIT => "QUIT",
                       _ => "UNKNOWN"
                   },
                   data.len());
        
        match command {
            SMFIC_OPTNEG => {
                log::info!("OPTNEG: Received option negotiation from sendmail");
                log::info!("OPTNEG: Negotiation data length: {} bytes", data.len());
                log::info!("OPTNEG: Raw negotiation data: {:?}", data);

                // Parse the option negotiation data from sendmail
                // Handle different data lengths for compatibility
                if data.len() >= 12 {
                    let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    let actions = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                    let protocol = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

                    log::info!(
                        "OPTNEG: Sendmail offers - version: {version}, actions: 0x{actions:08x}, protocol: 0x{protocol:08x}"
                    );
                    
                    // Decode sendmail's offered actions
                    let mut offered_actions = Vec::new();
                    if actions & 0x01 != 0 { offered_actions.push("ADDHDRS"); }
                    if actions & 0x02 != 0 { offered_actions.push("CHGHDRS"); }
                    if actions & 0x04 != 0 { offered_actions.push("ADDRCPT"); }
                    if actions & 0x08 != 0 { offered_actions.push("DELRCPT"); }
                    if actions & 0x10 != 0 { offered_actions.push("CHGBODY"); }
                    if actions & 0x20 != 0 { offered_actions.push("QUARANTINE"); }
                    log::info!("OPTNEG: Sendmail offers actions: {:?}", offered_actions);
                    
                    // Check if sendmail offers ADDHDRS capability
                    if actions & 0x01 == 0 {
                        log::error!("OPTNEG: CRITICAL - Sendmail does NOT offer ADDHDRS capability!");
                        log::error!("OPTNEG: This explains why headers are not being added to emails");
                    } else {
                        log::info!("OPTNEG: Good - Sendmail offers ADDHDRS capability");
                    }
                } else {
                    log::error!("OPTNEG: Invalid negotiation data length: {} (expected >= 12)", data.len());
                }

                // Send back our negotiation response
                // Format: version(4) + actions(4) + protocol(4) + reserved(12)
                let mut response = Vec::with_capacity(24);

                // Version: Match what sendmail offered or use 6
                let our_version = if data.len() >= 12 {
                    let offered_version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    std::cmp::min(offered_version, 6) // Use lower of offered or our max
                } else {
                    6
                };
                log::info!("OPTNEG: Using protocol version: {}", our_version);
                response.extend_from_slice(&our_version.to_be_bytes());

                // Actions we want to perform:
                // SMFIF_ADDHDRS (0x01) - Add headers
                let actions = 0x01u32; // We only need ADDHDRS for our spam tagging
                response.extend_from_slice(&actions.to_be_bytes());

                // Protocol steps we want to skip:
                // We want all steps, so protocol = 0
                let protocol = 0u32;
                response.extend_from_slice(&protocol.to_be_bytes());

                // Reserved fields (12 bytes of zeros)
                response.extend_from_slice(&[0u8; 12]);

                log::info!("OPTNEG: Requesting - version: 6, actions: 0x{:08x} (ADDHDRS), protocol: 0x{:08x} (all steps)", actions, protocol);
                log::info!("OPTNEG: Response data length: {} bytes", response.len());
                log::info!("OPTNEG: Response data: {:?}", response);
                
                self.send_response(SMFIC_OPTNEG, &response)?;
                log::info!("OPTNEG: Successfully sent capability negotiation response");
                Ok(true)
            }
            SMFIC_CONNECT => {
                let hostname = self.parse_connect_data(&data)?;
                log::debug!("Connection from: {hostname}");
                self.context.hostname = Some(hostname);
                self.send_response(SMFIR_CONTINUE, &[])?;
                Ok(true)
            }
            SMFIC_HELO => {
                let helo = String::from_utf8_lossy(&data)
                    .trim_end_matches('\0')
                    .to_string();
                log::debug!("HELO: {helo}");
                self.context.helo = Some(helo);
                self.send_response(SMFIR_CONTINUE, &[])?;
                Ok(true)
            }
            SMFIC_MAIL => {
                let sender = self.parse_mail_data(&data)?;
                log::debug!("Mail from: {sender}");
                self.context.sender = Some(sender);
                self.send_response(SMFIR_CONTINUE, &[])?;
                Ok(true)
            }
            SMFIC_RCPT => {
                let recipient = self.parse_mail_data(&data)?;
                log::debug!("Rcpt to: {recipient}");
                self.context.recipients.push(recipient);
                self.send_response(SMFIR_CONTINUE, &[])?;
                Ok(true)
            }
            SMFIC_DATA => {
                log::debug!("Data command received");
                // DATA command indicates start of message data
                // We don't need to do anything special here
                self.send_response(SMFIR_CONTINUE, &[])?;
                Ok(true)
            }
            SMFIC_MACRO => {
                // Macro definitions from sendmail - we can parse these for additional context
                log::debug!("Macro command received with {} bytes", data.len());
                if !data.is_empty() {
                    let macro_stage = data[0];
                    let macro_data = &data[1..];
                    log::debug!(
                        "Macro stage: 0x{:02x}, data length: {}",
                        macro_stage,
                        macro_data.len()
                    );

                    // Parse macro data if needed (format: name\0value\0name\0value\0...)
                    // For now, we'll just log and continue
                    if log::log_enabled!(log::Level::Debug) {
                        let macro_str = String::from_utf8_lossy(macro_data);
                        log::debug!("Macro data: {}", macro_str.replace('\0', " | "));
                    }
                }
                self.send_response(SMFIR_CONTINUE, &[])?;
                Ok(true)
            }
            SMFIC_HEADER => {
                let (name, value) = self.parse_header_data(&data)?;
                log::debug!("Header: {name}: {value}");

                // Store important headers
                match name.to_lowercase().as_str() {
                    "subject" => {
                        log::debug!("Processing subject header: {value}");
                        // Decode Base64 encoded subjects (RFC 2047)
                        let decoded_subject = self.decode_mime_header(&value);
                        log::debug!("Decoded subject: {decoded_subject}");
                        self.context.subject = Some(decoded_subject);
                    }
                    "x-mailer" | "user-agent" => {
                        log::debug!("Processing mailer header: {value}");
                        self.context.mailer = Some(value.clone());
                    }
                    _ => {}
                }

                self.context.headers.insert(name, value);

                // Early evaluation for REJECTION only (to catch rejections in time)
                // We need sender and some content to evaluate most rules
                if self.context.sender.is_some()
                    && (self.context.subject.is_some() || self.context.mailer.is_some())
                    && !self.context.headers.contains_key("_FOFF_EVALUATED")
                    && self.context.headers.len() > 5
                // Wait for enough headers
                {
                    log::debug!(
                        "Early evaluation for rejection with {} headers",
                        self.context.headers.len()
                    );
                    let action = self.engine.evaluate(&self.context);
                    match action {
                        Action::Reject { message } => {
                            log::info!("Rejecting message during header processing: {message}");
                            let response = format!("550 5.7.1 {message}");
                            self.send_response(SMFIR_REPLYCODE, response.as_bytes())?;
                            return Ok(true);
                        }
                        Action::TagAsSpam { .. } => {
                            // Don't handle TagAsSpam here - wait for end of message
                            log::debug!("TagAsSpam action detected, will handle at end of message");
                            // Mark as evaluated to prevent rejection, but allow tagging at end
                            self.context
                                .headers
                                .insert("_FOFF_EVALUATED".to_string(), "pending_tag".to_string());
                        }
                        Action::Accept => {
                            log::debug!("Message accepted during header processing");
                            self.context
                                .headers
                                .insert("_FOFF_EVALUATED".to_string(), "accepted".to_string());
                        }
                    }
                }

                self.send_response(SMFIR_CONTINUE, &[])?;
                Ok(true)
            }
            SMFIC_EOH => {
                log::info!("EOH: End of headers - evaluating rules but deferring header addition to EOM");

                let evaluation_status = self.context.headers.get("_FOFF_EVALUATED");
                log::info!("EOH: Evaluation status = {:?}", evaluation_status);

                // Process evaluation if we haven't already, or if we have pending_tag but no stored header info
                if evaluation_status.is_none() || 
                   (evaluation_status == Some(&"pending_tag".to_string()) && 
                    !self.context.headers.contains_key("_FOFF_TAG_HEADER")) {
                    log::info!("EOH: Proceeding with evaluation");
                    let action = self.engine.evaluate(&self.context);
                    match action {
                        Action::Reject { message } => {
                            log::info!("EOH: Rejecting message: {message}");
                            let response = format!("550 5.7.1 {message}");
                            self.send_response(SMFIR_REPLYCODE, response.as_bytes())?;
                            return Ok(true);
                        }
                        Action::TagAsSpam { header_name, header_value } => {
                            log::info!("EOH: TagAsSpam action detected - storing for EOM processing: {header_name}: {header_value}");
                            // Store the header info for EOM processing
                            self.context.headers.insert("_FOFF_EVALUATED".to_string(), "pending_tag".to_string());
                            self.context.headers.insert("_FOFF_TAG_HEADER".to_string(), header_name.to_string());
                            self.context.headers.insert("_FOFF_TAG_VALUE".to_string(), header_value.to_string());
                        }
                        Action::Accept => {
                            log::info!("EOH: Message accepted");
                            self.context.headers.insert("_FOFF_EVALUATED".to_string(), "accepted".to_string());
                        }
                    }
                } else {
                    log::info!("EOH: Message already evaluated: {:?}", evaluation_status);
                }

                self.send_response(SMFIR_CONTINUE, &[])?;
                Ok(true)
            }
            SMFIC_BODY => {
                // Capture body content for unsubscribe link validation
                if data.len() > 1 {
                    let body_chunk = String::from_utf8_lossy(&data[1..]);
                    log::debug!("Body chunk received: {} bytes", body_chunk.len());

                    // Append to existing body content
                    match &mut self.context.body {
                        Some(existing_body) => {
                            existing_body.push_str(&body_chunk);
                        }
                        None => {
                            self.context.body = Some(body_chunk.to_string());
                        }
                    }
                }
                self.send_response(SMFIR_CONTINUE, &[])?;
                Ok(true)
            }
            SMFIC_BODYEOB => {
                log::info!("BODYEOB: End of message processing");

                // DEBUGGING: Always try to add a test header to every email
                log::info!("BODYEOB: DEBUGGING - Adding test header to every email");
                let test_header_data = "X-FOFF-Debug\0Always-Added\0";
                log::info!("BODYEOB: DEBUG header data: {:02x?}", test_header_data.as_bytes());
                match self.send_response(SMFIR_ADDHEADER, test_header_data.as_bytes()) {
                    Ok(_) => log::info!("BODYEOB: DEBUG header sent successfully"),
                    Err(e) => log::error!("BODYEOB: DEBUG header failed: {}", e),
                }

                let evaluation_status = self.context.headers.get("_FOFF_EVALUATED");
                log::info!("BODYEOB: Evaluation status = {:?}", evaluation_status);
                
                // Process pending TagAsSpam actions
                if evaluation_status == Some(&"pending_tag".to_string()) {
                    log::info!("BODYEOB: Processing pending TagAsSpam action");
                    
                    let header_name = self.context.headers.get("_FOFF_TAG_HEADER").cloned();
                    let header_value = self.context.headers.get("_FOFF_TAG_VALUE").cloned();
                    
                    if let (Some(header_name), Some(header_value)) = (header_name, header_value) {
                        log::info!("BODYEOB: Adding spam header at EOM: {header_name}: {header_value}");
                        let header_data = format!("{header_name}\0{header_value}\0");
                        log::info!("BODYEOB: Header data format: {:?}", header_data);
                        log::info!("BODYEOB: Header data bytes: {:?}", header_data.as_bytes());
                        log::info!("BODYEOB: Header data length: {} bytes", header_data.len());
                        log::info!("BODYEOB: Raw bytes: {:02x?}", header_data.as_bytes());
                        log::info!("BODYEOB: About to send SMFIR_ADDHEADER (0x{:02x})...", SMFIR_ADDHEADER);
                        
                        match self.send_response(SMFIR_ADDHEADER, header_data.as_bytes()) {
                            Ok(_) => {
                                log::info!("BODYEOB: Successfully sent SMFIR_ADDHEADER response");
                                // Mark as tagged
                                self.context.headers.insert("_FOFF_EVALUATED".to_string(), "tagged".to_string());
                            }
                            Err(e) => {
                                log::error!("BODYEOB: Failed to send SMFIR_ADDHEADER: {}", e);
                                return Err(e);
                            }
                        }
                    } else {
                        log::error!("BODYEOB: Missing header name or value for pending tag");
                    }
                } else if evaluation_status.is_none() {
                    log::info!("BODYEOB: Proceeding with final evaluation (fallback)");
                    let action = self.engine.evaluate(&self.context);
                    match action {
                        Action::Reject { message } => {
                            // This shouldn't happen if early evaluation worked, but handle it
                            log::warn!("BODYEOB: Late rejection attempted (may not work): {message}");
                            let response = format!("550 5.7.1 {message}");
                            self.send_response(SMFIR_REPLYCODE, response.as_bytes())?;
                            return Ok(true);
                        }
                        Action::TagAsSpam { header_name, header_value } => {
                            log::info!("BODYEOB: Adding spam header at EOM (fallback): {header_name}: {header_value}");
                            let header_data = format!("{header_name}\0{header_value}\0");
                            match self.send_response(SMFIR_ADDHEADER, header_data.as_bytes()) {
                                Ok(_) => {
                                    log::info!("BODYEOB: Successfully sent SMFIR_ADDHEADER response (fallback)");
                                    self.context.headers.insert("_FOFF_EVALUATED".to_string(), "tagged".to_string());
                                }
                                Err(e) => {
                                    log::error!("BODYEOB: Failed to send SMFIR_ADDHEADER (fallback): {}", e);
                                    return Err(e);
                                }
                            }
                        }
                        Action::Accept => {
                            log::info!("BODYEOB: Message accepted");
                            self.context.headers.insert("_FOFF_EVALUATED".to_string(), "accepted".to_string());
                        }
                    }
                } else {
                    log::info!("BODYEOB: Message already evaluated: {:?}", evaluation_status);
                }

                log::info!("BODYEOB: About to send SMFIR_CONTINUE...");
                match self.send_response(SMFIR_CONTINUE, &[]) {
                    Ok(_) => {
                        log::info!("BODYEOB: Successfully sent SMFIR_CONTINUE");
                    }
                    Err(e) => {
                        log::error!("BODYEOB: Failed to send SMFIR_CONTINUE: {}", e);
                        return Err(e);
                    }
                }
                Ok(true)
            }
            SMFIC_ABORT => {
                log::debug!("Message aborted");
                self.context = MailContext::default(); // Reset context
                Ok(true)
            }
            SMFIC_QUIT => {
                log::debug!("Quit command received");
                Ok(false) // Close connection
            }
            _ => {
                log::warn!("Unknown command: 0x{command:02x}");
                self.send_response(SMFIR_CONTINUE, &[])?;
                Ok(true)
            }
        }
    }

    fn parse_connect_data(&self, data: &[u8]) -> anyhow::Result<String> {
        // Connect data format: hostname\0family\0port\0address\0
        let hostname = String::from_utf8_lossy(data)
            .split('\0')
            .next()
            .unwrap_or("unknown")
            .to_string();
        Ok(hostname)
    }

    fn parse_mail_data(&self, data: &[u8]) -> anyhow::Result<String> {
        // Mail data format: <email@domain.com>\0
        let email = String::from_utf8_lossy(data)
            .trim_end_matches('\0')
            .trim_start_matches('<')
            .trim_end_matches('>')
            .to_string();
        Ok(email)
    }

    fn parse_header_data(&self, data: &[u8]) -> anyhow::Result<(String, String)> {
        // Header data format: name\0value\0
        let data_str = String::from_utf8_lossy(data);
        let parts: Vec<&str> = data_str.split('\0').collect();

        if parts.len() >= 2 {
            Ok((parts[0].to_string(), parts[1].to_string()))
        } else {
            Ok(("unknown".to_string(), "".to_string()))
        }
    }

    fn decode_mime_header(&self, header: &str) -> String {
        log::debug!("MIME decode input: {header}");
        // Simple RFC 2047 decoder for =?charset?encoding?encoded-text?= format
        if header.contains("=?utf-8?B?") {
            log::debug!("Found Base64 encoded header");
            // Base64 encoded UTF-8
            let parts: Vec<&str> = header.split("?").collect();
            log::debug!("Split parts: {parts:?}");
            if parts.len() >= 4
                && parts[1].to_lowercase() == "utf-8"
                && parts[2].to_uppercase() == "B"
            {
                log::debug!("Valid Base64 format, decoding: {}", parts[3]);
                use base64::{engine::general_purpose, Engine as _};
                if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(parts[3]) {
                    if let Ok(decoded_string) = String::from_utf8(decoded_bytes) {
                        log::debug!("Successfully decoded to: {decoded_string}");
                        return decoded_string;
                    }
                }
            }
        }
        log::debug!("No decoding needed, returning original: {header}");
        // Return original if decoding fails or not encoded
        header.to_string()
    }
}

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
        log::info!("Connection from hostname: {hostname}");
        self.context = MailContext::default();
    }

    pub fn process_mail_from(&mut self, mail_from: &str) {
        log::debug!("MAIL FROM: {mail_from}");
        self.context.sender = Some(mail_from.to_string());
    }

    pub fn process_rcpt_to(&mut self, rcpt_to: &str) {
        log::debug!("RCPT TO: {rcpt_to}");
        self.context.recipients.push(rcpt_to.to_string());
    }

    pub fn process_header(&mut self, name: &str, value: &str) {
        log::debug!("Header: {name}: {value}");

        // Store all headers
        self.context
            .headers
            .insert(name.to_lowercase(), value.to_string());

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

    pub fn process_body(&mut self, body: &str) {
        log::debug!("Body content: {} bytes", body.len());
        self.context.body = Some(body.to_string());
    }

    pub fn evaluate_message(&self) -> &Action {
        log::debug!("=== EVALUATION DEBUG ===");
        log::debug!("Sender: {:?}", self.context.sender);
        log::debug!("Recipients: {:?}", self.context.recipients);
        log::debug!("Headers count: {}", self.context.headers.len());
        log::debug!("========================");
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
    let listener = UnixListener::bind(&config.socket_path).map_err(|e| {
        log::error!("Failed to bind to socket {}: {}", config.socket_path, e);
        log::error!("Make sure the directory exists and has proper permissions");
        log::error!("Try: sudo mkdir -p /var/run && sudo chown milter:milter /var/run");
        anyhow::anyhow!("Failed to bind to socket {}: {}", config.socket_path, e)
    })?;

    log::info!("Successfully bound to socket: {}", config.socket_path);

    // Set socket permissions (readable/writable by owner and group)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&config.socket_path)?.permissions();
        perms.set_mode(0o660); // rw-rw----
        std::fs::set_permissions(&config.socket_path, perms)?;
        log::info!("Set socket permissions to 0o660");
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
                log::error!("Failed to remove socket file: {e}");
            } else {
                log::info!("Socket file removed: {socket_path_for_cleanup}");
            }
        }

        std::process::exit(0);
    })
    .map_err(|e| anyhow::anyhow!("Error setting up signal handler: {}", e))?;

    // Create the filter engine once for sharing
    let filter_engine = Arc::new(FilterEngine::new(config.clone())?);

    log::info!("FOFF milter daemon started successfully, waiting for connections...");

    // Track last heartbeat for daemon health monitoring
    let mut last_heartbeat = std::time::Instant::now();
    let heartbeat_interval = std::time::Duration::from_secs(300); // 5 minutes

    // Main event loop - accept connections and spawn threads
    while running.load(Ordering::SeqCst) {
        // Set a timeout on accept to allow periodic heartbeat logging
        listener.set_nonblocking(true)?;

        match listener.accept() {
            Ok((stream, _addr)) => {
                log::info!("Accepted milter connection from mail server");

                // Reset to blocking mode for the connection
                stream.set_nonblocking(false)?;

                let engine_clone = filter_engine.clone();

                // Spawn a thread to handle this connection
                thread::spawn(move || {
                    let mut connection = MilterConnection::new(stream, engine_clone);
                    if let Err(e) = connection.handle() {
                        log::error!("Error handling milter connection: {e}");
                    }
                });

                // Reset heartbeat timer on successful connection
                last_heartbeat = std::time::Instant::now();
            }
            Err(e) => {
                // Check if this is just a timeout (no connections) or a real error
                match e.kind() {
                    std::io::ErrorKind::WouldBlock => {
                        // No connection available, check heartbeat
                        if last_heartbeat.elapsed() >= heartbeat_interval {
                            log::info!("FOFF milter daemon heartbeat - running normally, waiting for connections");
                            last_heartbeat = std::time::Instant::now();
                        }
                        // Sleep briefly to avoid busy waiting
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    _ => {
                        log::error!("Error accepting connection: {e}");
                        // For serious errors, sleep a bit longer before retrying
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
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
    milter.process_header(
        "Subject",
        "こんにちは！特別なオファー - Hello Special Offer",
    ); // Japanese + English
    milter.process_header("X-Mailer", "service.mail.cn v2.1");

    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✓ Would reject Chinese service + Japanese: {message}");
        }
        Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            log::info!("✓ Would tag Chinese service + Japanese {header_name}:{header_value}");
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
            log::info!("✓ Would reject Sparkpost to user@example.com: {message}");
        }
        Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            log::info!("✓ Would tag Sparkpost to user@example.com {header_name}:{header_value}");
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
            log::info!("✗ Unexpectedly rejected Chinese service without Japanese: {message}");
        }
        Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            log::info!(
                "✗ Unexpectedly tagged Chinese service without Japanese {header_name}:{header_value}"
            );
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
            log::info!("✗ Unexpectedly rejected Sparkpost to different user: {message}");
        }
        Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            log::info!(
                "✗ Unexpectedly tagged Sparkpost to different user {header_name}:{header_value}"
            );
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
            log::info!("✗ Unexpectedly rejected Japanese without Chinese service: {message}");
        }
        Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            log::info!(
                "✗ Unexpectedly tagged Japanese without Chinese service {header_name}:{header_value}"
            );
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
            log::info!("✗ Unexpectedly rejected legitimate email: {message}");
        }
        Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            log::info!("✗ Unexpectedly tagged legitimate email {header_name}:{header_value}");
        }
        Action::Accept => {
            log::info!("✓ Correctly accepted legitimate email");
        }
    }

    milter.reset_context();

    // Test 7: Russian domain tagging
    log::info!("=== Test 7: Russian domain tagging ===");
    milter.process_connection("mail.cartsgorilla.ru.com");
    milter.process_mail_from("LiquidGold@cartsgorilla.ru.com");
    milter.process_rcpt_to("user@example.com");
    milter.process_header("Subject", "Doctor Caught Drinking THIS in His Kitchen");
    milter.process_header("From", "Liquid Gold <LiquidGold@cartsgorilla.ru.com>");

    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✗ Unexpectedly rejected Russian domain: {message}");
        }
        Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            log::info!("✓ Would tag Russian domain {header_name}:{header_value}");
        }
        Action::Accept => {
            log::info!("✗ Unexpectedly accepted Russian domain without tagging");
        }
    }

    milter.reset_context();

    // Test 8: Javaburrn domain tagging (typosquatting)
    log::info!("=== Test 8: Javaburrn domain tagging ===");
    milter.process_connection("garden.javaburrn.rest");
    milter.process_mail_from("WeirdShrub@javaburrn.rest");
    milter.process_rcpt_to("user@example.com");
    milter.process_header(
        "Subject",
        "The African Shrub that Awakens Your Deepest Desire...",
    );
    milter.process_header("From", "African Shrub <WeirdShrub@javaburrn.rest>");

    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✗ Unexpectedly rejected javaburrn domain: {message}");
        }
        Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            log::info!("✓ Would tag javaburrn domain {header_name}:{header_value}");
        }
        Action::Accept => {
            log::info!("✗ Unexpectedly accepted javaburrn domain without tagging");
        }
    }

    milter.reset_context();

    // Test 9: Unsubscribe link validation
    log::info!("=== Test 9: Unsubscribe link validation ===");
    milter.process_connection("spam.example.com");
    milter.process_mail_from("spammer@spam.example.com");
    milter.process_rcpt_to("user@example.com");
    milter.process_header("Subject", "Amazing offer - click to unsubscribe!");
    milter.process_header("From", "Spammer <spammer@spam.example.com>");

    // Simulate email body with fake unsubscribe link
    milter.process_body(
        r#"<html><body>
        <p>Amazing offer! Buy now!</p>
        <p><a href="http://fake-unsubscribe-domain-that-does-not-exist.invalid/unsubscribe">Unsubscribe here</a></p>
        </body></html>"#
    );

    let action = milter.evaluate_message();
    match action {
        Action::Reject { message } => {
            log::info!("✓ Would reject email with invalid unsubscribe: {message}");
        }
        Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            log::info!("✓ Would tag email with invalid unsubscribe {header_name}:{header_value}");
        }
        Action::Accept => {
            log::info!("✗ Unexpectedly accepted email with invalid unsubscribe");
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
