use chrono::Utc;
use rusqlite::{params, Connection};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Sender};

#[derive(Debug, Clone)]
pub struct OwnedLogEntry {
    pub timestamp: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub headers: String,
    pub query_params: Option<String>,
    pub body_snippet: Option<String>,
    pub attack_type: String,
    pub rule_id: String,
    pub severity: String,
    pub action_taken: String,
    pub status_code: i32,
    pub blocked_reason: Option<String>,
}

pub struct LogEntry<'a> {
    pub client_ip: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub headers: &'a str,
    pub query_params: Option<&'a str>,
    pub body_snippet: Option<&'a str>,
    pub attack_type: &'a str,
    pub rule_id: &'a str,
    pub severity: &'a str,
    pub action_taken: &'a str,
    pub status_code: i32,
    pub blocked_reason: Option<&'a str>,
}

pub struct WafLogger {
    sender: Sender<OwnedLogEntry>,
    current_mode: Arc<AtomicU8>, // 0 = Prevention, 1 = Detection
    db_path: String,
}

impl WafLogger {
    pub fn new(db_path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;

        // High-performance SQLite engine tuning
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -64000;
             PRAGMA temp_store = MEMORY;
             CREATE TABLE IF NOT EXISTS waf_logs (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp TEXT NOT NULL,
                 client_ip TEXT NOT NULL,
                 method TEXT NOT NULL,
                 path TEXT NOT NULL,
                 headers TEXT,
                 query_params TEXT,
                 body_snippet TEXT,
                 attack_type TEXT NOT NULL,
                 rule_id TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 action_taken TEXT NOT NULL,
                 status_code INTEGER NOT NULL,
                 blocked_reason TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON waf_logs(timestamp);
             CREATE INDEX IF NOT EXISTS idx_logs_attack_type ON waf_logs(attack_type);
             CREATE INDEX IF NOT EXISTS idx_logs_action ON waf_logs(action_taken);

             CREATE TABLE IF NOT EXISTS waf_config (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             INSERT OR IGNORE INTO waf_config (key, value) VALUES ('mode', 'PREVENTION');",
        )?;

        // Read initial mode into fast atomic RAM cache
        let initial_mode = {
            let mut stmt = conn.prepare("SELECT value FROM waf_config WHERE key = 'mode'").unwrap();
            let mut rows = stmt.query([]).unwrap();
            if let Ok(Some(row)) = rows.next() {
                row.get::<_, String>(0).unwrap_or_else(|_| "PREVENTION".to_string())
            } else {
                "PREVENTION".to_string()
            }
        };

        let mode_byte = if initial_mode.eq_ignore_ascii_case("DETECTION") { 1 } else { 0 };
        let current_mode = Arc::new(AtomicU8::new(mode_byte));

        // Create high-capacity async MPSC buffer (25,000 entries)
        let (sender, mut receiver) = channel::<OwnedLogEntry>(25_000);

        // Spawn dedicated background task for high-throughput batch writes
        let bg_db_path = db_path.to_string();
        tokio::spawn(async move {
            let mut bg_conn = match Connection::open(&bg_db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[WAF Logger] Failed to open background SQLite connection: {}", e);
                    return;
                }
            };

            let _ = bg_conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;");

            let mut batch: Vec<OwnedLogEntry> = Vec::with_capacity(500);
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(50));

            loop {
                tokio::select! {
                    maybe_entry = receiver.recv() => {
                        match maybe_entry {
                            Some(entry) => {
                                batch.push(entry);
                                if batch.len() >= 500 {
                                    flush_batch(&mut bg_conn, &mut batch);
                                }
                            }
                            None => {
                                if !batch.is_empty() {
                                    flush_batch(&mut bg_conn, &mut batch);
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            flush_batch(&mut bg_conn, &mut batch);
                        }
                    }
                }
            }
        });

        Ok(Self {
            sender,
            current_mode,
            db_path: db_path.to_string(),
        })
    }

    /// Non-blocking, zero-latency event logging via Tokio MPSC bounded queue
    pub fn log_event(&self, entry: LogEntry) {
        let timestamp = Utc::now().to_rfc3339();
        let owned = OwnedLogEntry {
            timestamp,
            client_ip: entry.client_ip.to_string(),
            method: entry.method.to_string(),
            path: entry.path.to_string(),
            headers: entry.headers.to_string(),
            query_params: entry.query_params.map(|s| s.to_string()),
            body_snippet: entry.body_snippet.map(|s| s.to_string()),
            attack_type: entry.attack_type.to_string(),
            rule_id: entry.rule_id.to_string(),
            severity: entry.severity.to_string(),
            action_taken: entry.action_taken.to_string(),
            status_code: entry.status_code,
            blocked_reason: entry.blocked_reason.map(|s| s.to_string()),
        };

        // Try sending into channel without blocking Tokio worker threads
        let _ = self.sender.try_send(owned);
    }

    /// Sub-nanosecond in-memory atomic retrieval of WAF operation mode (Zero SQL queries)
    pub fn get_config_mode(&self) -> String {
        match self.current_mode.load(Ordering::Relaxed) {
            1 => "DETECTION".to_string(),
            _ => "PREVENTION".to_string(),
        }
    }

    /// Updates WAF mode in RAM atomic cache
    pub fn set_config_mode(&self, mode: &str) {
        let val = if mode.eq_ignore_ascii_case("DETECTION") { 1 } else { 0 };
        self.current_mode.store(val, Ordering::SeqCst);
    }

    /// Returns aggregated SOC statistics and breakdown of threats
    pub fn get_stats(&self) -> serde_json::Value {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => {
                return serde_json::json!({
                    "total_inspected": 0,
                    "blocked": 0,
                    "passed": 0,
                    "flagged": 0,
                    "block_ratio": 0.0,
                    "threat_breakdown": {},
                    "top_attackers": []
                });
            }
        };

        let total: i64 = conn.query_row("SELECT COUNT(*) FROM waf_logs", [], |r| r.get(0)).unwrap_or(0);
        let blocked: i64 = conn.query_row("SELECT COUNT(*) FROM waf_logs WHERE action_taken = 'BLOCKED'", [], |r| r.get(0)).unwrap_or(0);
        let passed: i64 = conn.query_row("SELECT COUNT(*) FROM waf_logs WHERE action_taken = 'PASSED'", [], |r| r.get(0)).unwrap_or(0);
        let flagged: i64 = conn.query_row("SELECT COUNT(*) FROM waf_logs WHERE action_taken = 'FLAGGED'", [], |r| r.get(0)).unwrap_or(0);

        let mut threat_breakdown = serde_json::Map::new();
        if let Ok(mut stmt) = conn.prepare("SELECT attack_type, COUNT(*) FROM waf_logs WHERE attack_type != 'CLEAN' GROUP BY attack_type ORDER BY COUNT(*) DESC") {
            if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))) {
                for item in rows.flatten() {
                    threat_breakdown.insert(item.0, serde_json::Value::from(item.1));
                }
            }
        }

        let mut top_attackers = Vec::new();
        if let Ok(mut stmt) = conn.prepare("SELECT client_ip, COUNT(*) FROM waf_logs WHERE action_taken = 'BLOCKED' GROUP BY client_ip ORDER BY COUNT(*) DESC LIMIT 5") {
            if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))) {
                for item in rows.flatten() {
                    top_attackers.push(serde_json::json!({
                        "ip": item.0,
                        "count": item.1
                    }));
                }
            }
        }

        let ratio = if total > 0 {
            ((blocked as f64 / total as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        };

        serde_json::json!({
            "total_inspected": total,
            "blocked": blocked,
            "passed": passed,
            "flagged": flagged,
            "block_ratio": ratio,
            "threat_breakdown": threat_breakdown,
            "top_attackers": top_attackers
        })
    }

    /// Retrieves paginated security incidents for SOC stream
    pub fn get_logs(&self, limit: usize, attack_type: Option<&str>) -> Vec<serde_json::Value> {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut logs = Vec::new();
        let query = if let Some(at) = attack_type {
            if at != "ALL" && !at.is_empty() {
                format!("SELECT id, timestamp, client_ip, method, path, attack_type, rule_id, severity, action_taken, status_code, blocked_reason, query_params, body_snippet FROM waf_logs WHERE attack_type = '{}' ORDER BY id DESC LIMIT {}", at.replace('\'', "''"), limit)
            } else {
                format!("SELECT id, timestamp, client_ip, method, path, attack_type, rule_id, severity, action_taken, status_code, blocked_reason, query_params, body_snippet FROM waf_logs ORDER BY id DESC LIMIT {}", limit)
            }
        } else {
            format!("SELECT id, timestamp, client_ip, method, path, attack_type, rule_id, severity, action_taken, status_code, blocked_reason, query_params, body_snippet FROM waf_logs ORDER BY id DESC LIMIT {}", limit)
        };

        if let Ok(mut stmt) = conn.prepare(&query) {
            let rows = stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "id": row.get::<_, i64>(0)?,
                    "timestamp": row.get::<_, String>(1)?,
                    "client_ip": row.get::<_, String>(2)?,
                    "method": row.get::<_, String>(3)?,
                    "path": row.get::<_, String>(4)?,
                    "attack_type": row.get::<_, String>(5)?,
                    "rule_id": row.get::<_, String>(6)?,
                    "severity": row.get::<_, String>(7)?,
                    "action_taken": row.get::<_, String>(8)?,
                    "status_code": row.get::<_, i32>(9)?,
                    "blocked_reason": row.get::<_, Option<String>>(10)?,
                    "query_params": row.get::<_, Option<String>>(11)?,
                    "body_snippet": row.get::<_, Option<String>>(12)?,
                }))
            });

            if let Ok(mapped) = rows {
                for entry in mapped.flatten() {
                    logs.push(entry);
                }
            }
        }

        logs
    }

    /// Truncates the security log table
    pub fn clear_logs(&self) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute("DELETE FROM waf_logs", [])?;
        Ok(())
    }

    /// Returns persistent configuration keys
    pub fn get_config(&self) -> serde_json::Value {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return serde_json::json!({"mode": self.get_config_mode()}),
        };

        let mut config_map = serde_json::Map::new();
        config_map.insert("mode".to_string(), serde_json::Value::from(self.get_config_mode()));

        if let Ok(mut stmt) = conn.prepare("SELECT key, value FROM waf_config") {
            if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
                for (k, v) in rows.flatten() {
                    config_map.insert(k, serde_json::Value::from(v));
                }
            }
        }

        serde_json::Value::Object(config_map)
    }

    /// Updates persistent configuration in SQLite and updates RAM atomic cache if needed
    pub fn update_config(&self, key: &str, value: &str) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute(
            "INSERT OR REPLACE INTO waf_config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;

        if key.eq_ignore_ascii_case("mode") {
            self.set_config_mode(value);
        }

        Ok(())
    }
}

/// Flushes batch of log records into SQLite using a single WAL transaction
fn flush_batch(conn: &mut Connection, batch: &mut Vec<OwnedLogEntry>) {
    if batch.is_empty() {
        return;
    }

    if let Ok(tx) = conn.transaction() {
        {
            let mut stmt = match tx.prepare_cached(
                "INSERT INTO waf_logs (
                    timestamp, client_ip, method, path, headers, query_params,
                    body_snippet, attack_type, rule_id, severity, action_taken,
                    status_code, blocked_reason
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            ) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[WAF Logger] Failed to prepare cached statement: {}", e);
                    batch.clear();
                    return;
                }
            };

            for entry in batch.drain(..) {
                let _ = stmt.execute(params![
                    entry.timestamp,
                    entry.client_ip,
                    entry.method,
                    entry.path,
                    entry.headers,
                    entry.query_params,
                    entry.body_snippet,
                    entry.attack_type,
                    entry.rule_id,
                    entry.severity,
                    entry.action_taken,
                    entry.status_code,
                    entry.blocked_reason,
                ]);
            }
        }
        let _ = tx.commit();
    }
}
