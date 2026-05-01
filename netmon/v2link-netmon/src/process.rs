use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use v2link_netmon_common::{AppCounters, AppIdentity, SOURCE_NETMON_EBPF};

use crate::ebpf::PidCounter;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub uid: u32,
    pub name: String,
    pub executable_path: String,
    pub cgroup_path: Option<String>,
}

pub fn scan_processes() -> HashMap<u32, ProcessInfo> {
    let mut processes = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return processes;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if let Some(info) = read_process(pid, entry.path()) {
            processes.insert(pid, info);
        }
    }
    processes
}

pub fn to_app_counters(info: &ProcessInfo, counter: &PidCounter, timestamp: String) -> AppCounters {
    let display_name = if is_xray(info) {
        "Xray Core / Proxy Tunnel".to_string()
    } else {
        info.name.clone()
    };
    let identity = AppIdentity {
        app_id: app_id(&info.executable_path, info.uid),
        name: display_name,
        executable_path: info.executable_path.clone(),
        uid: Some(counter.uid),
        pid: Some(info.pid),
        cgroup_path: info.cgroup_path.clone(),
    };
    AppCounters {
        identity,
        rx_bytes: counter.rx_bytes,
        tx_bytes: counter.tx_bytes,
        download_bps: 0.0,
        upload_bps: 0.0,
        confidence: "high".to_string(),
        source: SOURCE_NETMON_EBPF.to_string(),
        last_seen: timestamp,
    }
}

fn read_process(pid: u32, proc_path: PathBuf) -> Option<ProcessInfo> {
    let name = read_comm(&proc_path).unwrap_or_else(|| format!("pid-{pid}"));
    let uid = read_uid(&proc_path).unwrap_or(0);
    let executable_path = fs::read_link(proc_path.join("exe"))
        .ok()
        .and_then(|path| path.to_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| name.clone());
    let cgroup_path = read_cgroup(&proc_path);
    Some(ProcessInfo {
        pid,
        uid,
        name,
        executable_path,
        cgroup_path,
    })
}

fn read_comm(proc_path: &Path) -> Option<String> {
    fs::read_to_string(proc_path.join("comm"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_uid(proc_path: &Path) -> Option<u32> {
    let status = fs::read_to_string(proc_path.join("status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse::<u32>().ok();
        }
    }
    None
}

fn read_cgroup(proc_path: &Path) -> Option<String> {
    fs::read_to_string(proc_path.join("cgroup"))
        .ok()
        .and_then(|value| value.lines().next().map(ToOwned::to_owned))
}

fn is_xray(info: &ProcessInfo) -> bool {
    let name = info.name.to_ascii_lowercase();
    let executable = info.executable_path.to_ascii_lowercase();
    name.contains("xray") || executable.ends_with("/xray") || executable.contains("xray-core")
}

fn app_id(executable_path: &str, uid: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(executable_path.as_bytes());
    hasher.update(b":");
    hasher.update(uid.to_string().as_bytes());
    format!("app-{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_id_is_stable() {
        assert_eq!(
            app_id("/usr/bin/firefox", 1000),
            app_id("/usr/bin/firefox", 1000)
        );
        assert_ne!(
            app_id("/usr/bin/firefox", 1000),
            app_id("/usr/bin/code", 1000)
        );
    }

    #[test]
    fn xray_is_classified_as_proxy_tunnel() {
        let info = ProcessInfo {
            pid: 10,
            uid: 0,
            name: "xray".to_string(),
            executable_path: "/usr/bin/xray".to_string(),
            cgroup_path: None,
        };
        let counter = PidCounter {
            pid: 10,
            uid: 0,
            rx_bytes: 1,
            tx_bytes: 2,
        };
        let app = to_app_counters(&info, &counter, "2026-05-01T00:00:00Z".to_string());
        assert_eq!(app.identity.name, "Xray Core / Proxy Tunnel");
    }
}
