# v2link-netmon

`v2link-netmon` is the optional local helper for per-application traffic attribution.

It is separate from the PyQt GUI. The GUI never runs as root. In v0.2.4 the daemon runs as the dedicated non-login `v2link-netmon` account with no Linux capabilities because the production eBPF backend is not implemented.

## Current State

This workspace provides:

- `v2link-netmon`: Unix socket daemon and JSON API
- `v2link-netmon-common`: shared API/data structures
- `v2link-netmon-ebpf`: placeholder crate for the future Aya eBPF object
- SQLite app traffic schema compatible with the GUI
- Process identity resolution from `/proc`
- Xray classification as `Xray Core / Proxy Tunnel`
- Versioned status diagnostics that report `backend-not-implemented`

The daemon does not capture packet payloads, URLs, DNS contents, messages, tokens, cookies, or private content.
It does not fabricate per-application counters.

## API

Default socket:

```text
/run/v2link-client/netmon.sock
```

The socket is mode `0660` and available only to the service account/group. Debian installation does not enable or start the service and does not add desktop users to the group. Administrator opt-in is:

```bash
sudo usermod -aG v2link-netmon "$USER"
sudo systemctl enable --now v2link-netmon
```

Log out and back in after changing group membership.

Endpoints:

- `GET /status`
- `GET /live`
- `GET /apps/today`
- `GET /apps/history?days=30`
- `GET /diagnostics`

## Build And Test

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

## Limitation

The production Aya eBPF program is not bundled. The API reports the daemon as reachable but non-operational with stable reason `backend-not-implemented`, and app endpoints return empty lists. Prompt 3B must implement the backend and reassess the service privilege model before any capability is granted.
