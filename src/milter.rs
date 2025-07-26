use crate::config::{Action, Config};
use crate::filter::{FilterEngine, MailContext};
use indymilter::{run, Actions, Callbacks, Config as IndyConfig, ContextActions, Status};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UnixListener;

pub struct Milter {
    engine: Arc<FilterEngine>,
}

// Simple state storage with unique session IDs
type StateMap = Arc<Mutex<HashMap<u64, MailContext>>>;
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

impl Milter {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let engine = Arc::new(FilterEngine::new(config)?);
        Ok(Milter { engine })
    }

    pub async fn run(&self, socket_path: &str) -> anyhow::Result<()> {
        let instance_id = std::process::id();
        log::info!("Starting milter on: {socket_path} (PID: {instance_id})");
        // Remove existing socket if it exists
        if std::path::Path::new(socket_path).exists() {
            std::fs::remove_file(socket_path)?;
        }

        let listener = UnixListener::bind(socket_path)?;
        let engine = self.engine.clone();
        let state: StateMap = Arc::new(Mutex::new(HashMap::new()));

        // Create callbacks with explicit type annotation
        let callbacks: Callbacks<()> = Callbacks {
            connect: Some(Box::new({
                let state = state.clone();
                move |_ctx: &mut indymilter::Context<()>, hostname, _addr| {
                    let state = state.clone();
                    Box::pin(async move {
                        let hostname_str = hostname.to_string_lossy().to_string();
                        let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
                        log::debug!("Connection from: {hostname_str} (Session: {session_id})");
                        let mail_ctx = MailContext {
                            hostname: Some(hostname_str),
                            ..Default::default()
                        };
                        state.lock().unwrap().insert(session_id, mail_ctx);
                        // Store session ID in context private data
                        _ctx.set_private_data(session_id);
                        Status::Continue
                    })
                }
            })),

            mail: Some(Box::new({
                let state = state.clone();
                move |_ctx: &mut indymilter::Context<()>, sender| {
                    let state = state.clone();
                    Box::pin(async move {
                        let sender_str = sender
                            .iter()
                            .map(|s| s.to_string_lossy())
                            .collect::<Vec<_>>()
                            .join(",");
                        log::debug!("Mail from: {sender_str}");
                        // Update the context for this session
                        if let Some(session_id) = _ctx.get_private_data::<u64>() {
                        if let Some(mail_ctx) = state.lock().unwrap().get_mut(session_id) {
                            mail_ctx.sender = Some(sender_str);
                        }
                        }
                        Status::Continue
                    })
                }
            })),

            rcpt: Some(Box::new({
                let state = state.clone();
                move |_ctx: &mut indymilter::Context<()>, recipient| {
                    let state = state.clone();
                    Box::pin(async move {
                        let recipient_str = recipient
                            .iter()
                            .map(|s| s.to_string_lossy())
                            .collect::<Vec<_>>()
                            .join(",");
                        log::debug!("Rcpt to: {recipient_str}");
                        let connection_id = format!("{:p}", _ctx as *const _);
                        if let Some(mail_ctx) = state.lock().unwrap().get_mut(&connection_id) {
                            mail_ctx.recipients.push(recipient_str);
                        }
                        Status::Continue
                    })
                }
            })),

            header: Some(Box::new({
                let state = state.clone();
                move |_ctx: &mut indymilter::Context<()>, name, value| {
                    let state = state.clone();
                    Box::pin(async move {
                        let name_str = name.to_string_lossy().to_string();
                        let value_str = value.to_string_lossy().to_string();
                        log::debug!("Header: {name_str}: {value_str}");

                        let connection_id = format!("{:p}", _ctx as *const _);
                        if let Some(mail_ctx) = state.lock().unwrap().get_mut(&connection_id) {
                            // Store important headers
                            match name_str.to_lowercase().as_str() {
                                "subject" => {
                                    mail_ctx.subject = Some(value_str.clone());
                                }
                                "x-mailer" | "user-agent" => {
                                    mail_ctx.mailer = Some(value_str.clone());
                                }
                                _ => {}
                            }
                            mail_ctx.headers.insert(name_str, value_str);
                        }
                        Status::Continue
                    })
                }
            })),

            body: Some(Box::new({
                let state = state.clone();
                move |_ctx: &mut indymilter::Context<()>, body_chunk| {
                    let state = state.clone();
                    Box::pin(async move {
                        let body_str = String::from_utf8_lossy(&body_chunk);
                        let connection_id = format!("{:p}", _ctx as *const _);
                        if let Some(mail_ctx) = state.lock().unwrap().get_mut(&connection_id) {
                            match &mut mail_ctx.body {
                                Some(existing_body) => {
                                    existing_body.push_str(&body_str);
                                }
                                None => {
                                    mail_ctx.body = Some(body_str.to_string());
                                }
                            }
                        }
                        Status::Continue
                    })
                }
            })),

            eom: Some(Box::new({
                let engine = engine.clone();
                let state = state.clone();
                move |_ctx: &mut indymilter::EomContext<()>| {
                    let engine = engine.clone();
                    let state = state.clone();
                    Box::pin(async move {
                        // Clone mail context to avoid holding mutex across await
                        let connection_id = format!("{:p}", _ctx as *const _);
                        let mail_ctx_clone = state.lock().unwrap().get(&connection_id).cloned();
                        
                        // Clean up the state for this connection
                        state.lock().unwrap().remove(&connection_id);

                        if let Some(mail_ctx) = mail_ctx_clone {
                            let sender = mail_ctx.sender.as_deref().unwrap_or("<unknown>");
                            let recipients = if mail_ctx.recipients.is_empty() {
                                "<unknown>".to_string()
                            } else {
                                mail_ctx.recipients.join(", ")
                            };

                            let action = engine.evaluate(&mail_ctx).await;
                            log::debug!("PID {} evaluated action: {:?}", std::process::id(), action);

                            match action {
                                Action::Reject { message } => {
                                    log::info!(
                                        "REJECT from={sender} to={recipients} reason={message}"
                                    );
                                    return Status::Reject;
                                }
                                Action::TagAsSpam {
                                    header_name,
                                    header_value,
                                } => {
                                    log::info!("TAG from={sender} to={recipients} header={header_name}:{header_value}");
                                    log::debug!("Adding header: {header_name}={header_value}");
                                    // Add the spam header
                                    if let Err(e) = _ctx
                                        .actions
                                        .add_header(header_name.clone(), header_value.clone())
                                        .await
                                    {
                                        log::error!("Failed to add header: {e}");
                                    } else {
                                        log::debug!("Successfully added header: {header_name}={header_value}");
                                    }
                                    return Status::Accept;
                                }
                                Action::Accept => {
                                    log::info!("ACCEPT from={sender} to={recipients}");
                                    return Status::Accept;
                                }
                            }
                        }

                        Status::Accept
                    })
                }
            })),

            ..Default::default()
        };

        // Configure indymilter to enable ADD_HEADER action
        let config = IndyConfig {
            actions: Actions::ADD_HEADER,
            ..Default::default()
        };

        run(listener, callbacks, config, tokio::signal::ctrl_c()).await?;
        Ok(())
    }
}
