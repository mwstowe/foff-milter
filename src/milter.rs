use crate::config::{Action, Config};
use crate::filter::{FilterEngine, MailContext};
use indymilter::{run, Actions, Callbacks, Config as IndyConfig, ContextActions, Status};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::UnixListener;

pub struct Milter {
    engine: Arc<FilterEngine>,
}

// Simple state storage
type StateMap = Arc<Mutex<HashMap<String, MailContext>>>;

impl Milter {

    pub fn new(config: Config) -> anyhow::Result<Self> {
        let engine = Arc::new(FilterEngine::new(config)?);
        Ok(Milter { engine })
    }

    pub async fn run(&self, socket_path: &str) -> anyhow::Result<()> {
        log::info!("Starting milter on: {}", socket_path);
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
                        log::debug!("Connection from: {}", hostname_str);
                        let mail_ctx = MailContext {
                            hostname: Some(hostname_str.clone()),
                            ..Default::default()
                        };
                        state.lock().unwrap().insert(hostname_str, mail_ctx);
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
                        log::debug!("Mail from: {}", sender_str);
                        // Update the most recent context
                        if let Some((_, mail_ctx)) = state.lock().unwrap().iter_mut().last() {
                            mail_ctx.sender = Some(sender_str);
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
                        log::debug!("Rcpt to: {}", recipient_str);
                        if let Some((_, mail_ctx)) = state.lock().unwrap().iter_mut().last() {
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
                        log::debug!("Header: {}: {}", name_str, value_str);

                        if let Some((_, mail_ctx)) = state.lock().unwrap().iter_mut().last() {
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
                        if let Some((_, mail_ctx)) = state.lock().unwrap().iter_mut().last() {
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
                        log::info!("End of message - evaluating");

                        // Clone mail context to avoid holding mutex across await
                        let mail_ctx_clone = state.lock().unwrap().values().last().cloned();

                        if let Some(mail_ctx) = mail_ctx_clone {
                            let action = engine.evaluate(&mail_ctx);

                            match action {
                                Action::Reject { message } => {
                                    log::info!("Rejecting message: {}", message);
                                    return Status::Reject;
                                }
                                Action::TagAsSpam {
                                    header_name,
                                    header_value,
                                } => {
                                    log::info!(
                                        "Tagging as spam: {}: {}",
                                        header_name,
                                        header_value
                                    );
                                    // Add the spam header
                                    if let Err(e) = _ctx
                                        .actions
                                        .add_header(header_name.clone(), header_value.clone())
                                        .await
                                    {
                                        log::error!("Failed to add header: {}", e);
                                    }
                                    return Status::Accept;
                                }
                                Action::Accept => {
                                    log::info!("Accepting message");
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
