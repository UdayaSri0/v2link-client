use std::path::{Path, PathBuf};

use anyhow::Result;
use rusqlite::{params, Connection};
use v2link_netmon_common::AppCounters;

#[derive(Debug, Clone)]
pub struct NetmonDb {
    path: PathBuf,
}

impl NetmonDb {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    pub fn migrate(&self) -> Result<()> {
        let conn = self.connect()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS apps (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                executable_path TEXT NOT NULL,
                desktop_id TEXT NULL,
                icon_name TEXT NULL,
                uid INTEGER NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                trusted_identity INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS app_traffic_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                rx_bytes INTEGER NOT NULL DEFAULT 0,
                tx_bytes INTEGER NOT NULL DEFAULT 0,
                rx_delta_bytes INTEGER NOT NULL DEFAULT 0,
                tx_delta_bytes INTEGER NOT NULL DEFAULT 0,
                download_bps REAL NOT NULL DEFAULT 0,
                upload_bps REAL NOT NULL DEFAULT 0,
                source TEXT NOT NULL,
                confidence TEXT NOT NULL DEFAULT 'unknown'
            );
            CREATE TABLE IF NOT EXISTS daily_app_usage (
                date TEXT NOT NULL,
                app_id TEXT NOT NULL,
                rx_bytes INTEGER NOT NULL DEFAULT 0,
                tx_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(date, app_id)
            );
            CREATE TABLE IF NOT EXISTS app_tracking_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                detail TEXT NULL
            );
            ",
        )?;
        Ok(())
    }

    pub fn record_app_sample(&self, app: &AppCounters) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "
            INSERT INTO apps(id, name, executable_path, uid, first_seen, last_seen, trusted_identity)
            VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                executable_path = excluded.executable_path,
                uid = excluded.uid,
                last_seen = excluded.last_seen
            ",
            params![
                app.identity.app_id,
                app.identity.name,
                app.identity.executable_path,
                app.identity.uid,
                app.last_seen,
            ],
        )?;
        conn.execute(
            "
            INSERT INTO app_traffic_samples(
                app_id, timestamp, rx_bytes, tx_bytes, rx_delta_bytes, tx_delta_bytes,
                download_bps, upload_bps, source, confidence
            )
            VALUES (?1, ?2, ?3, ?4, ?3, ?4, ?5, ?6, ?7, ?8)
            ",
            params![
                app.identity.app_id,
                app.last_seen,
                app.rx_bytes,
                app.tx_bytes,
                app.download_bps,
                app.upload_bps,
                app.source,
                app.confidence,
            ],
        )?;
        conn.execute(
            "
            INSERT INTO daily_app_usage(date, app_id, rx_bytes, tx_bytes)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(date, app_id) DO UPDATE SET
                rx_bytes = daily_app_usage.rx_bytes + excluded.rx_bytes,
                tx_bytes = daily_app_usage.tx_bytes + excluded.tx_bytes
            ",
            params![
                app.last_seen.get(0..10).unwrap_or(&app.last_seen),
                app.identity.app_id,
                app.rx_bytes,
                app.tx_bytes,
            ],
        )?;
        Ok(())
    }

    fn connect(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "busy_timeout", 3000)?;
        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2link_netmon_common::AppIdentity;

    #[test]
    fn creates_schema_and_records_sample() {
        let temp =
            std::env::temp_dir().join(format!("v2link-netmon-test-{}.sqlite3", std::process::id()));
        let _ = std::fs::remove_file(&temp);
        let db = NetmonDb::open(&temp).expect("db open");
        db.migrate().expect("migrate");
        let app = AppCounters {
            identity: AppIdentity {
                app_id: "app-test".to_string(),
                name: "Test".to_string(),
                executable_path: "/usr/bin/test".to_string(),
                uid: Some(1000),
                pid: Some(1),
                cgroup_path: None,
            },
            rx_bytes: 10,
            tx_bytes: 20,
            download_bps: 0.0,
            upload_bps: 0.0,
            confidence: "high".to_string(),
            source: "netmon-ebpf".to_string(),
            last_seen: "2026-05-01T00:00:00Z".to_string(),
        };
        db.record_app_sample(&app).expect("record");
        let _ = std::fs::remove_file(temp);
    }
}
