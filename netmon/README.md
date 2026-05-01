# v2link-netmon

`v2link-netmon` is the optional local helper for per-application traffic attribution.

It is separate from the PyQt GUI. The GUI never runs as root. The helper is intended to run as a system service with only the privileges/capabilities required to load network accounting programs and expose read-only local stats.

## Current State

This workspace provides:

- `v2link-netmon`: Unix socket daemon and JSON API
- `v2link-netmon-common`: shared API/data structures
- `v2link-netmon-ebpf`: placeholder crate for the future Aya eBPF object
- SQLite app traffic schema compatible with the GUI
- Process identity resolution from `/proc`
- Xray classification as `Xray Core / Proxy Tunnel`
- Graceful diagnostics when eBPF is unavailable

The daemon does not capture packet payloads, URLs, DNS contents, messages, tokens, cookies, or private content.

## API

Default socket:

```text
/run/v2link-client/netmon.sock
```

Endpoints:

- `GET /status`
- `GET /live`
- `GET /apps/today`
- `GET /apps/history?days=30`
- `GET /diagnostics`

## Build And Test

```bash
cargo fmt --all -- --check
cargo clippy -- -D warnings
cargo test
```

## Limitation

The production Aya eBPF program is not bundled yet. Until that backend is implemented and loaded successfully, the daemon reports `ebpf-unavailable` and returns no fabricated per-app counters.
