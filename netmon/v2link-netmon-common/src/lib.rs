use serde::{Deserialize, Serialize};

pub const DEFAULT_SYSTEM_SOCKET: &str = "/run/v2link-client/netmon.sock";
pub const SOURCE_NETMON_EBPF: &str = "netmon-ebpf";
pub const SOURCE_NETMON_PROC: &str = "netmon-proc";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppIdentity {
    pub app_id: String,
    pub name: String,
    pub executable_path: String,
    pub uid: Option<u32>,
    pub pid: Option<u32>,
    pub cgroup_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCounters {
    pub identity: AppIdentity,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub download_bps: f64,
    pub upload_bps: f64,
    pub confidence: String,
    pub source: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub installed: bool,
    pub running: bool,
    pub backend: String,
    pub permission_ok: bool,
    pub kernel_supported: bool,
    pub started_at: String,
    pub message: String,
    pub socket_path: String,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveResponse {
    pub timestamp: String,
    pub apps: Vec<AppCounters>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsResponse {
    pub status: StatusResponse,
    pub tracked_processes: usize,
    pub tracked_apps: usize,
    pub database_path: String,
    pub proxy_attribution_note: String,
    pub privacy_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryResponse {
    pub timestamp: String,
    pub days: u32,
    pub apps: Vec<AppCounters>,
}
