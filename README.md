# v2link-client

Linux desktop client for V2Ray-style links built with Python 3.11+ and PyQt6.

Current status: **early beta** — the app currently supports **`vless://`** links (a useful subset) and runs **Xray-core** under the hood.

## Screenshots

<p>
  <img src="images/app-dark.png" width="900" alt="v2link-client (Dark)" />
</p>

<p>
  <img src="images/app-light.png" width="900" alt="v2link-client (Light)" />
</p>

## Features

- Paste a `vless://` link → validate → start/stop the core
- Ping server (TCP/TLS) + built-in speed test (through the tunnel)
- Live session metrics: uptime, upload/download speed, total traffic used
- Local proxy inbounds:
  - SOCKS5 on `127.0.0.1:<port>`
  - HTTP proxy on `127.0.0.1:<port>`
- Connectivity indicator: `CONNECTING` / `ONLINE` / `DEGRADED` / `OFFLINE`
- Built-in diagnostics and log access
- About dialog (Help -> About)
- Light/Dark theme toggle (saved to your profile)

## Requirements (runtime)

- Linux desktop (GNOME/KDE/etc.)
- Python **3.11+**
- **Xray-core** available in your `PATH` (`xray version` should work)

## Installation (run from source)

1) Install system packages (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip
```

2) Install Xray-core:

```bash
xray version
```

If that command fails, install `xray` using your distro’s package manager or from the upstream project and make sure it’s on your `PATH`.

3) Create a virtual environment and install Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

4) Run the app:

```bash
./scripts/dev_run.sh
```

## Usage

1) Paste your `vless://` link.
2) Click **Validate & Save**.
3) Click **Start**.
4) To proxy the whole system, enable **System Proxy** (recommended).  
   If you prefer manual setup, configure your browser/app to use the proxy:
   - Click **Copy manual proxy settings** in the app and paste them where needed.

Notes:
- The app defaults to SOCKS5 `127.0.0.1:1080` and HTTP `127.0.0.1:8080`, but will pick free ports if those are busy.
- The selected theme is saved in your profile and restored on next launch.
- System proxy auto-apply currently targets GNOME/libproxy via `gsettings`. Other desktops may require manual proxy setup.

## Supported link subset (today)

`vless://` with:
- `security=tls` or `security=none`
- transports: `type=tcp`, `type=ws`, `type=grpc`
- optional: `sni`, `fp` (fingerprint), `alpn`, `allowInsecure`, `flow`
- TCP `headerType=none` (and limited support for `headerType=http`)

Not supported yet:
- `vmess://`, `trojan://`, `ss://`
- REALITY, advanced XTLS options, complex routing rules, multiple profiles

## Logs & data locations

- Config/profile: `~/.config/v2link-client/profile.json`
- State + generated core config: `~/.local/state/v2link-client/`
- Logs: `~/.local/state/v2link-client/logs/`
  - `app.log` (app logs)
  - `xray_access.log`, `xray_error.log`, `xray_stdout.log`

## Troubleshooting

### Connectivity shows OFFLINE / SSL EOF errors

This usually means the tunnel is not working end-to-end (server down/blocked, wrong TLS/SNI, etc.).

Common cause: the link sets an `sni=...` that does not match the server certificate **while** `allowInsecure=0`.
In that case, TLS verification fails and the proxy tunnel may drop during handshake.

What to try:
- Remove `sni` or set it to the server host (or set `allowInsecure=1` if you understand the risk).
- Check the logs via **Open logs folder**.

## Development

Developer deps:

```bash
source .venv/bin/activate
pip install -r requirements-dev.txt
```

Run tests:

```bash
PYTHONPATH=src python -m pytest -q
```

## Author

Udaya Sri

## License

MIT License

Copyright (c) 2026 Udaya Sri
