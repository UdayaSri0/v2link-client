use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use chrono::SecondsFormat;
use serde::Serialize;
use v2link_netmon_common::{DiagnosticsResponse, HistoryResponse, LiveResponse};

use crate::{privacy_note, proxy_attribution_note, SharedState};

pub fn serve(socket_path: PathBuf, state: Arc<Mutex<SharedState>>) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating socket directory {}", parent.display()))?;
    }
    if socket_path.exists() {
        fs::remove_file(&socket_path)
            .with_context(|| format!("removing stale socket {}", socket_path.display()))?;
    }
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding socket {}", socket_path.display()))?;
    set_socket_permissions(&socket_path)?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(err) = handle_client(stream, state) {
                        eprintln!("netmon API request failed: {err:#}");
                    }
                });
            }
            Err(err) => eprintln!("netmon API accept failed: {err}"),
        }
    }
    Ok(())
}

fn set_socket_permissions(socket_path: &std::path::Path) -> Result<()> {
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))
        .with_context(|| format!("setting socket permissions {}", socket_path.display()))
}

fn handle_client(mut stream: UnixStream, state: Arc<Mutex<SharedState>>) -> Result<()> {
    let mut buffer = [0_u8; 4096];
    let read = stream.read(&mut buffer)?;
    let request = String::from_utf8_lossy(&buffer[..read]);
    let path = parse_path(&request);
    let guard = state
        .lock()
        .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;

    match path {
        Some("/status") => write_json(&mut stream, 200, &guard.status()),
        Some("/live") => {
            let response = LiveResponse {
                timestamp: now_iso(),
                status: guard.status(),
                apps: guard.apps.values().cloned().collect(),
            };
            write_json(&mut stream, 200, &response)
        }
        Some("/apps/today") => {
            let response = LiveResponse {
                timestamp: now_iso(),
                status: guard.status(),
                apps: guard.apps.values().cloned().collect(),
            };
            write_json(&mut stream, 200, &response)
        }
        Some(path) if path.starts_with("/apps/history") => {
            let response = HistoryResponse {
                timestamp: now_iso(),
                status: guard.status(),
                days: parse_days(path),
                apps: guard.apps.values().cloned().collect(),
            };
            write_json(&mut stream, 200, &response)
        }
        Some("/diagnostics") => {
            let response = DiagnosticsResponse {
                status: guard.status(),
                tracked_processes: 0,
                tracked_apps: guard.apps.len(),
                database_path: guard.database_path.clone(),
                proxy_attribution_note: proxy_attribution_note().to_string(),
                privacy_note: privacy_note().to_string(),
            };
            write_json(&mut stream, 200, &response)
        }
        _ => write_json(&mut stream, 404, &serde_json::json!({"error": "not found"})),
    }
}

fn parse_path(request: &str) -> Option<&str> {
    let first_line = request.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    if method != "GET" {
        return None;
    }
    parts.next()
}

fn parse_days(path: &str) -> u32 {
    path.split_once("days=")
        .and_then(|(_, rest)| rest.split('&').next())
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(30)
}

fn write_json<T: Serialize>(stream: &mut UnixStream, status: u16, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    let status_text = if status == 200 { "OK" } else { "Not Found" };
    write!(
        stream,
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    Ok(())
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_days() {
        assert_eq!(parse_days("/apps/history?days=7"), 7);
        assert_eq!(parse_days("/apps/history"), 30);
    }

    #[test]
    fn parses_get_path() {
        assert_eq!(parse_path("GET /status HTTP/1.1\r\n\r\n"), Some("/status"));
        assert_eq!(parse_path("POST /status HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_path("malformed"), None);
    }

    #[test]
    fn socket_permissions_are_group_only() {
        let path =
            std::env::temp_dir().join(format!("v2link-netmon-socket-mode-{}", std::process::id()));
        fs::write(&path, b"fixture").expect("create fixture");
        set_socket_permissions(&path).expect("set socket mode");
        let mode = fs::metadata(&path)
            .expect("fixture metadata")
            .permissions()
            .mode()
            & 0o777;
        fs::remove_file(&path).expect("remove fixture");
        assert_eq!(mode, 0o660);
    }

    #[test]
    fn parses_unknown_request_for_not_found_routing() {
        assert_eq!(
            parse_path("GET /unknown HTTP/1.1\r\n\r\n"),
            Some("/unknown")
        );
    }
}
