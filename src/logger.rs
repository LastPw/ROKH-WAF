use chrono::Utc;
use rusqlite::{params, Connection};
use std::sync::Mutex;

pub struct WafLogger {
    conn: Mutex<Connection>,
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

impl WafLogger {
    pub fn new(db_path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;
        
        // Performance optimizations for concurrent reads/writes
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
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
             );"
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn log_event(&self, entry: LogEntry) {
        let timestamp = Utc::now().to_rfc3339();
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT INTO waf_logs (
                    timestamp, client_ip, method, path, headers, query_params,
                    body_snippet, attack_type, rule_id, severity, action_taken,
                    status_code, blocked_reason
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    timestamp,
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
                ],
            );
        }
    }

    pub fn get_config_mode(&self) -> String {
        if let Ok(conn) = self.conn.lock() {
            let mut stmt = conn.prepare("SELECT value FROM waf_config WHERE key = 'mode'").ok().unwrap();
            let mut rows = stmt.query([]).ok().unwrap();
            if let Ok(Some(row)) = rows.next() {
                if let Ok(val) = row.get::<_, String>(0) {
                    return val;
                }
            }
        }
        "PREVENTION".to_string()
    }
}
