use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::interval;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleStats {
    pub rule_name: String,
    pub matches: u64,
    pub accepts: u64,
    pub rejects: u64,
    pub tags: u64,
    pub first_match: Option<DateTime<Utc>>,
    pub last_match: Option<DateTime<Utc>>,
    pub total_processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalStats {
    pub total_emails: u64,
    pub total_accepts: u64,
    pub total_rejects: u64,
    pub total_tags: u64,
    pub no_rule_matches: u64, // Emails that didn't match any rule
    pub start_time: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum StatEvent {
    RuleMatch {
        rule_name: String,
        action: String, // "Accept", "Reject", "TagAsSpam"
        processing_time_ms: u64,
    },
    NoRuleMatch,
    EmailProcessed,
}

pub struct StatisticsCollector {
    db_path: String,
    sender: mpsc::UnboundedSender<StatEvent>,
    _handle: tokio::task::JoinHandle<()>,
}

impl StatisticsCollector {
    pub fn new(db_path: String, flush_interval_seconds: u64) -> Result<Self> {
        // Create database directory if it doesn't exist
        if let Some(parent) = Path::new(&db_path).parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create stats directory: {}", parent.display())
            })?;
        }

        let (sender, receiver) = mpsc::unbounded_channel();

        let db_path_clone = db_path.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) =
                Self::stats_worker(db_path_clone, receiver, flush_interval_seconds).await
            {
                log::error!("Statistics worker error: {e}");
            }
        });

        Ok(Self {
            db_path,
            sender,
            _handle: handle,
        })
    }

    pub fn record_event(&self, event: StatEvent) {
        if let Err(e) = self.sender.send(event) {
            log::warn!("Failed to send statistics event: {e}");
        }
    }

    async fn stats_worker(
        db_path: String,
        mut receiver: mpsc::UnboundedReceiver<StatEvent>,
        flush_interval_seconds: u64,
    ) -> Result<()> {
        let conn = Arc::new(Mutex::new(Self::init_database(&db_path)?));
        let mut buffer: HashMap<String, RuleStats> = HashMap::new();
        let mut global_stats = Self::load_global_stats(&conn)?;

        let mut flush_timer = interval(Duration::from_secs(flush_interval_seconds));
        let mut last_flush = Instant::now();

        loop {
            tokio::select! {
                event = receiver.recv() => {
                    match event {
                        Some(event) => {
                            Self::process_event(event, &mut buffer, &mut global_stats);
                        }
                        None => {
                            // Channel closed, flush and exit
                            Self::flush_to_database(&conn, &buffer, &global_stats)?;
                            break;
                        }
                    }
                }
                _ = flush_timer.tick() => {
                    if last_flush.elapsed() >= Duration::from_secs(flush_interval_seconds) {
                        if let Err(e) = Self::flush_to_database(&conn, &buffer, &global_stats) {
                            log::error!("Failed to flush statistics: {e}");
                        } else {
                            buffer.clear();
                            last_flush = Instant::now();
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn process_event(
        event: StatEvent,
        buffer: &mut HashMap<String, RuleStats>,
        global_stats: &mut GlobalStats,
    ) {
        let now = Utc::now();
        global_stats.last_updated = now;

        match event {
            StatEvent::EmailProcessed => {
                global_stats.total_emails += 1;
            }
            StatEvent::NoRuleMatch => {
                global_stats.no_rule_matches += 1;
                global_stats.total_accepts += 1; // No rule match = default action (usually accept)
            }
            StatEvent::RuleMatch {
                rule_name,
                action,
                processing_time_ms,
            } => {
                let stats = buffer
                    .entry(rule_name.clone())
                    .or_insert_with(|| RuleStats {
                        rule_name: rule_name.clone(),
                        matches: 0,
                        accepts: 0,
                        rejects: 0,
                        tags: 0,
                        first_match: Some(now),
                        last_match: Some(now),
                        total_processing_time_ms: 0,
                    });

                stats.matches += 1;
                stats.last_match = Some(now);
                stats.total_processing_time_ms += processing_time_ms;

                match action.as_str() {
                    "Accept" => {
                        stats.accepts += 1;
                        global_stats.total_accepts += 1;
                    }
                    "Reject" => {
                        stats.rejects += 1;
                        global_stats.total_rejects += 1;
                    }
                    "TagAsSpam" => {
                        stats.tags += 1;
                        global_stats.total_tags += 1;
                    }
                    _ => {}
                }
            }
        }
    }

    fn init_database(db_path: &str) -> Result<Connection> {
        let conn = Connection::open(db_path)
            .with_context(|| format!("Failed to open statistics database: {db_path}"))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS rule_stats (
                rule_name TEXT PRIMARY KEY,
                matches INTEGER NOT NULL DEFAULT 0,
                accepts INTEGER NOT NULL DEFAULT 0,
                rejects INTEGER NOT NULL DEFAULT 0,
                tags INTEGER NOT NULL DEFAULT 0,
                first_match TEXT,
                last_match TEXT,
                total_processing_time_ms INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS global_stats (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                total_emails INTEGER NOT NULL DEFAULT 0,
                total_accepts INTEGER NOT NULL DEFAULT 0,
                total_rejects INTEGER NOT NULL DEFAULT 0,
                total_tags INTEGER NOT NULL DEFAULT 0,
                no_rule_matches INTEGER NOT NULL DEFAULT 0,
                start_time TEXT NOT NULL,
                last_updated TEXT NOT NULL
            )",
            [],
        )?;

        // Initialize global stats if not exists
        conn.execute(
            "INSERT OR IGNORE INTO global_stats (id, start_time, last_updated) VALUES (1, ?, ?)",
            params![Utc::now().to_rfc3339(), Utc::now().to_rfc3339()],
        )?;

        Ok(conn)
    }

    fn load_global_stats(conn: &Arc<Mutex<Connection>>) -> Result<GlobalStats> {
        let conn = conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT total_emails, total_accepts, total_rejects, total_tags, 
                    no_rule_matches, start_time, last_updated 
             FROM global_stats WHERE id = 1",
        )?;

        let stats = stmt.query_row([], |row| {
            Ok(GlobalStats {
                total_emails: row.get(0)?,
                total_accepts: row.get(1)?,
                total_rejects: row.get(2)?,
                total_tags: row.get(3)?,
                no_rule_matches: row.get(4)?,
                start_time: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                    .unwrap()
                    .with_timezone(&Utc),
                last_updated: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .unwrap()
                    .with_timezone(&Utc),
            })
        })?;

        Ok(stats)
    }

    fn flush_to_database(
        conn: &Arc<Mutex<Connection>>,
        buffer: &HashMap<String, RuleStats>,
        global_stats: &GlobalStats,
    ) -> Result<()> {
        let conn = conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;

        // Update global stats
        tx.execute(
            "UPDATE global_stats SET 
                total_emails = ?, total_accepts = ?, total_rejects = ?, total_tags = ?,
                no_rule_matches = ?, last_updated = ?
             WHERE id = 1",
            params![
                global_stats.total_emails,
                global_stats.total_accepts,
                global_stats.total_rejects,
                global_stats.total_tags,
                global_stats.no_rule_matches,
                global_stats.last_updated.to_rfc3339()
            ],
        )?;

        // Update rule stats
        for stats in buffer.values() {
            tx.execute(
                "INSERT OR REPLACE INTO rule_stats 
                 (rule_name, matches, accepts, rejects, tags, first_match, last_match, total_processing_time_ms)
                 VALUES (?, 
                         COALESCE((SELECT matches FROM rule_stats WHERE rule_name = ?), 0) + ?,
                         COALESCE((SELECT accepts FROM rule_stats WHERE rule_name = ?), 0) + ?,
                         COALESCE((SELECT rejects FROM rule_stats WHERE rule_name = ?), 0) + ?,
                         COALESCE((SELECT tags FROM rule_stats WHERE rule_name = ?), 0) + ?,
                         COALESCE((SELECT first_match FROM rule_stats WHERE rule_name = ?), ?),
                         ?,
                         COALESCE((SELECT total_processing_time_ms FROM rule_stats WHERE rule_name = ?), 0) + ?)",
                params![
                    stats.rule_name,
                    stats.rule_name, stats.matches,
                    stats.rule_name, stats.accepts,
                    stats.rule_name, stats.rejects,
                    stats.rule_name, stats.tags,
                    stats.rule_name, stats.first_match.map(|t| t.to_rfc3339()),
                    stats.last_match.map(|t| t.to_rfc3339()),
                    stats.rule_name, stats.total_processing_time_ms,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn get_stats(&self) -> Result<(GlobalStats, Vec<RuleStats>)> {
        let conn = Connection::open(&self.db_path)?;

        // Initialize database if it doesn't exist
        Self::init_database(&self.db_path)?;

        let global_stats = Self::load_global_stats(&Arc::new(Mutex::new(conn)))?;
        let conn = Connection::open(&self.db_path)?;

        let mut stmt = conn.prepare(
            "SELECT rule_name, matches, accepts, rejects, tags, first_match, last_match, total_processing_time_ms
             FROM rule_stats ORDER BY matches DESC"
        )?;

        let rule_stats = stmt
            .query_map([], |row| {
                Ok(RuleStats {
                    rule_name: row.get(0)?,
                    matches: row.get(1)?,
                    accepts: row.get(2)?,
                    rejects: row.get(3)?,
                    tags: row.get(4)?,
                    first_match: row.get::<_, Option<String>>(5)?.map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .unwrap()
                            .with_timezone(&Utc)
                    }),
                    last_match: row.get::<_, Option<String>>(6)?.map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .unwrap()
                            .with_timezone(&Utc)
                    }),
                    total_processing_time_ms: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok((global_stats, rule_stats))
    }

    pub fn get_unmatched_rules(&self, all_rule_names: &[String]) -> Result<Vec<String>> {
        let conn = Connection::open(&self.db_path)?;

        // Initialize database if it doesn't exist
        Self::init_database(&self.db_path)?;

        let mut stmt = conn.prepare("SELECT rule_name FROM rule_stats WHERE matches > 0")?;
        let matched_rules: std::collections::HashSet<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<std::collections::HashSet<_>, _>>()?;

        let unmatched: Vec<String> = all_rule_names
            .iter()
            .filter(|rule_name| !matched_rules.contains(*rule_name))
            .cloned()
            .collect();

        Ok(unmatched)
    }

    pub fn reset_stats(&self) -> Result<()> {
        let conn = Connection::open(&self.db_path)?;

        // Initialize database if it doesn't exist
        Self::init_database(&self.db_path)?;

        conn.execute("DELETE FROM rule_stats", [])?;
        conn.execute(
            "UPDATE global_stats SET 
                total_emails = 0, total_accepts = 0, total_rejects = 0, total_tags = 0,
                no_rule_matches = 0, start_time = ?, last_updated = ?
             WHERE id = 1",
            params![Utc::now().to_rfc3339(), Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }
}
