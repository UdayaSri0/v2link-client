use anyhow::Result;

#[derive(Debug, Clone)]
pub struct BackendStatus {
    pub name: String,
    pub permission_ok: bool,
    pub kernel_supported: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PidCounter {
    pub pid: u32,
    pub uid: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug)]
pub struct Backend {
    status: BackendStatus,
}

impl Backend {
    pub fn load() -> Self {
        let permission_ok = unsafe { libc::geteuid() == 0 };
        let message = if permission_ok {
            "Aya eBPF loader scaffold is present, but no production BPF program is bundled yet."
        } else {
            "v2link-netmon is not running with privileges required to load eBPF programs."
        };
        Self {
            status: BackendStatus {
                name: "ebpf-unavailable".to_string(),
                permission_ok,
                kernel_supported: false,
                message: message.to_string(),
            },
        }
    }

    pub fn status(&self) -> BackendStatus {
        self.status.clone()
    }

    pub fn read_counters(&mut self) -> Result<Vec<PidCounter>> {
        Ok(Vec::new())
    }
}
