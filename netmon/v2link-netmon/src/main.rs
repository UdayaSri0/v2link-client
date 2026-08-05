mod api;
mod db;
mod ebpf;
mod process;

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::SecondsFormat;
use v2link_netmon_common::{AppCounters, StatusResponse, API_VERSION, DEFAULT_SYSTEM_SOCKET};

const DEFAULT_DB_PATH: &str = "/var/lib/v2link-client/netmon.sqlite3";
const PROXY_ATTRIBUTION_NOTE: &str = "When system proxy is enabled, some app traffic may be represented under Xray because Xray performs the remote encrypted connection.";
const PRIVACY_NOTE: &str = "v2link-netmon records local process names, executable paths, UIDs, and byte counters only. It does not capture packet payloads, URLs, DNS contents, messages, tokens, or cookies.";

#[derive(Debug)]
pub struct SharedState {
    started_at: String,
    socket_path: String,
    database_path: String,
    backend: ebpf::BackendStatus,
    apps: HashMap<String, AppCounters>,
    last_error: Option<String>,
}

impl SharedState {
    fn status(&self) -> StatusResponse {
        StatusResponse {
            api_version: API_VERSION,
            installed: true,
            running: true,
            operational: self.backend.operational,
            backend: self.backend.name.clone(),
            backend_state: self.backend.state.clone(),
            reason_code: self.backend.reason_code.clone(),
            counters_available: self.backend.counters_available,
            permission_ok: self.backend.permission_ok,
            kernel_supported: self.backend.kernel_supported,
            started_at: self.started_at.clone(),
            message: self.backend.message.clone(),
            socket_path: self.socket_path.clone(),
            last_error: self.last_error.clone(),
        }
    }
}

fn main() -> Result<()> {
    let socket_path = socket_path();
    let database_path = database_path();
    let db = db::NetmonDb::open(&database_path)
        .with_context(|| format!("opening database {}", database_path.display()))?;
    db.migrate().context("migrating database")?;

    let backend = ebpf::Backend::load();
    let state = Arc::new(Mutex::new(SharedState {
        started_at: now_iso(),
        socket_path: socket_path.display().to_string(),
        database_path: database_path.display().to_string(),
        backend: backend.status(),
        apps: HashMap::new(),
        last_error: None,
    }));

    let sampler_state = Arc::clone(&state);
    thread::spawn(move || sampler_loop(sampler_state, backend, db));

    api::serve(socket_path, state).context("serving API")
}

fn sampler_loop(state: Arc<Mutex<SharedState>>, mut backend: ebpf::Backend, db: db::NetmonDb) {
    loop {
        if let Err(err) = sample_once(&state, &mut backend, &db) {
            if let Ok(mut guard) = state.lock() {
                guard.last_error = Some(err.to_string());
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn sample_once(
    state: &Arc<Mutex<SharedState>>,
    backend: &mut ebpf::Backend,
    db: &db::NetmonDb,
) -> Result<()> {
    let raw_counters = backend.read_counters()?;
    if raw_counters.is_empty() {
        return Ok(());
    }

    let processes = process::scan_processes();
    let mut apps = HashMap::new();
    for counter in raw_counters {
        if counter.rx_bytes == 0 && counter.tx_bytes == 0 {
            continue;
        }
        let Some(proc_info) = processes.get(&counter.pid) else {
            continue;
        };
        let app = process::to_app_counters(proc_info, &counter, now_iso());
        db.record_app_sample(&app)?;
        apps.insert(app.identity.app_id.clone(), app);
    }

    let mut guard = state
        .lock()
        .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
    guard.backend = backend.status();
    guard.apps = apps;
    guard.last_error = None;
    Ok(())
}

fn socket_path() -> PathBuf {
    if let Ok(value) = env::var("V2LINK_NETMON_SOCKET") {
        return PathBuf::from(value);
    }
    if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("v2link-client/netmon.sock");
    }
    PathBuf::from(DEFAULT_SYSTEM_SOCKET)
}

fn database_path() -> PathBuf {
    env::var("V2LINK_NETMON_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_DB_PATH))
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(crate) fn proxy_attribution_note() -> &'static str {
    PROXY_ATTRIBUTION_NOTE
}

pub(crate) fn privacy_note() -> &'static str {
    PRIVACY_NOTE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_schema_serializes_protocol_v2_fields() {
        let state = SharedState {
            started_at: "synthetic".into(),
            socket_path: DEFAULT_SYSTEM_SOCKET.into(),
            database_path: "/var/lib/v2link-client/netmon.sqlite3".into(),
            backend: ebpf::Backend::load().status(),
            apps: HashMap::new(),
            last_error: None,
        };
        let value = serde_json::to_value(state.status()).expect("serialize status");
        assert_eq!(value["api_version"], API_VERSION);
        assert_eq!(value["operational"], false);
        assert_eq!(value["reason_code"], "backend-not-implemented");
        assert_eq!(value["counters_available"], false);
    }
}
