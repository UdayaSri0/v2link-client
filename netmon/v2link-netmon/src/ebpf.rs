use anyhow::Result;

#[derive(Debug, Clone)]
pub struct BackendStatus {
    pub name: String,
    pub state: String,
    pub reason_code: String,
    pub operational: bool,
    pub counters_available: bool,
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
        Self {
            status: BackendStatus {
                name: "ebpf-unavailable".to_string(),
                state: "not-implemented".to_string(),
                reason_code: "backend-not-implemented".to_string(),
                operational: false,
                counters_available: false,
                permission_ok: true,
                kernel_supported: false,
                message:
                    "The production eBPF attribution backend is not implemented in this release."
                        .to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_backend_is_explicitly_non_operational() {
        let mut backend = Backend::load();
        let status = backend.status();
        assert_eq!(status.reason_code, "backend-not-implemented");
        assert_eq!(status.state, "not-implemented");
        assert!(!status.operational);
        assert!(!status.counters_available);
        assert!(backend.read_counters().expect("read counters").is_empty());
    }
}
