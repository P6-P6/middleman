//! The audit log. Every request is recorded, accepted or refused, with the reason.
//! Values are never stored, only who asked, for what, why, and what happened.
//! Otherwise the log would become the easiest thing to steal.
//!
//! Budgets are counted from this log, so they survive restarts.

use rusqlite::{params, Connection};
use std::path::Path;

pub struct Audit {
    conn: Connection,
}

pub struct Entry<'a> {
    pub requester: &'a str,
    pub machine: &'a str,
    pub transport: &'a str,
    pub action: &'a str,
    pub reason: &'a str,
    pub outcome: &'a str,
    pub detail: &'a str,
    pub rows: i64,
    pub level: i64,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS log (
    id        INTEGER PRIMARY KEY,
    ts        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    requester TEXT    NOT NULL,
    machine   TEXT    NOT NULL,
    transport TEXT    NOT NULL,
    action    TEXT    NOT NULL,
    reason    TEXT    NOT NULL,
    outcome   TEXT    NOT NULL,
    detail    TEXT    NOT NULL,
    rows      INTEGER NOT NULL DEFAULT 0,
    level     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS log_by_requester ON log (requester, ts);
CREATE TRIGGER IF NOT EXISTS log_no_update BEFORE UPDATE ON log
    BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS log_no_delete BEFORE DELETE ON log
    BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
";

impl Audit {
    pub fn open(path: &Path) -> Result<Audit, String> {
        let conn = Connection::open(path).map_err(|e| format!("cannot open audit log {}: {e}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_millis(2000)).map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| format!("cannot prepare audit log: {e}"))?;
        Ok(Audit { conn })
    }

    pub fn record(&self, e: &Entry) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO log (requester, machine, transport, action, reason, outcome, detail, rows, level)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![e.requester, e.machine, e.transport, e.action, e.reason, e.outcome, e.detail, e.rows, e.level],
            )
            .map(|_| ())
            .map_err(|e| format!("cannot write audit log: {e}"))
    }

    /// Calls made and rows returned or changed by `requester` in the last `window_secs`.
    pub fn usage(&self, requester: &str, window_secs: u32) -> Result<(u64, u64), String> {
        self.conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(rows), 0) FROM log
                 WHERE requester = ?1 AND ts >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)",
                params![requester, format!("-{window_secs} seconds")],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
            )
            .map_err(|e| format!("cannot read audit log: {e}"))
    }

    /// The latest `count` entries, newest first, as display strings.
    pub fn recent(&self, count: usize) -> Result<Vec<String>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ts, requester, machine, transport, action, reason, outcome, detail, rows, level
                 FROM log ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([count as i64], |r| {
                Ok(format!(
                    "{}  {:<20} {:<12} {:<9} {:<16} {:<10} {:<8} {:<26} rows={} level={}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, i64>(9)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }
}
