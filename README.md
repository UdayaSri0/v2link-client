# v2link-client

Linux desktop client for V2Ray-style links, built with Python 3.11+ and PyQt6, powered by Xray-core.

Current release target: **v0.2.0**

Project status: **beta** (stable for daily use, focused feature scope).

## Screenshots

<p>
  <img src="images/app-dark.png" width="900" alt="v2link-client (Dark)" />
</p>

<p>
  <img src="images/app-light.png" width="900" alt="v2link-client (Light)" />
</p>

## Key Features

- Validate and run `vless://` links through Xray-core
- Save/manage multiple profiles (favorite/default/duplicate/edit/delete)
- Validation persistence for saved profiles (no unnecessary revalidation)
- Local SOCKS5 + HTTP proxy endpoints (auto-select free ports when needed)
- Optional desktop system-proxy apply/restore while running
- Health indicator + ping + speed test + traffic/uptime metrics
- Traffic Monitor dashboard with Overview, Applications, Proxy Profiles, History, Settings, and Diagnostics tabs
- Local SQLite proxy/profile traffic history with daily totals, profile totals, session history, charts, and CSV export
- Optional per-application tracking preparation through the advanced `v2link-netmon` helper path
- Diagnostics panel with runtime proxy state and log access
- Cached performance diagnostics and a read-only runtime inspection script
- Built-in update check against GitHub Releases
- Light/Dark theme

## Runtime Requirements

- Linux desktop environment (GNOME/KDE/etc.)

Official AppImage, `.deb`, and APT releases include bundled Xray-core for normal operation. Source builds may use bundled vendor files from `./scripts/fetch_xray_core.sh` or a system `xray` from `PATH` as a fallback.

## Supported Install Methods

Primary supported release artifacts:

1. **AppImage**
2. **Debian package (`.deb`)**

Also available for Debian/Ubuntu users:

3. **APT repository** (published from release workflow)

## Install from AppImage

1. Download the latest AppImage from GitHub Releases.

Expected artifact name pattern:
- `v2link-client-<version>-linux-<arch>.AppImage`
- `<arch>` is `x86_64` or `aarch64`

2. Make executable and run:

```bash
chmod +x v2link-client-*.AppImage
./v2link-client-*.AppImage
```

3. Optional launcher setup:

```bash
mkdir -p ~/.local/bin
cp v2link-client-*.AppImage ~/.local/bin/v2link-client.AppImage
chmod +x ~/.local/bin/v2link-client.AppImage
```

Create `~/.local/share/applications/v2link-client.desktop`:

```ini
[Desktop Entry]
Name=v2link-client
Exec=/home/YOUR_USER/.local/bin/v2link-client.AppImage
Icon=v2link-client
Type=Application
Categories=Network;
Terminal=false
```

## Install from `.deb`

1. Download the latest `.deb` from GitHub Releases.

Expected artifact name pattern:
- `v2link-client_<version>_<arch>.deb`
- `<arch>` is `amd64` or `arm64`

2. Install:

```bash
sudo dpkg -i v2link-client_<version>_amd64.deb
sudo apt -f install
```

3. Launch:

```bash
v2link-client
```

## Install via APT Repository (Optional)

Import the repository key:

```bash
curl -fsSL https://udayasri0.github.io/v2link-client/apt/public.key \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/v2link-client-archive-keyring.gpg >/dev/null
```

Add the source list:

```bash
echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/v2link-client-archive-keyring.gpg] https://udayasri0.github.io/v2link-client/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/v2link-client.list >/dev/null
```

Install:

```bash
sudo apt update
sudo apt install v2link-client
```

## Run from Source

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
./scripts/dev_run.sh
```

## Local Build Instructions

Build AppImage only:

```bash
./scripts/build_appimage.sh
```

Build `.deb` only:

```bash
./scripts/build_deb.sh
```

Build full release set (PyInstaller + AppImage + `.deb` + checksums):

```bash
./scripts/build_release.sh
```

The release build fetches a pinned official Xray-core release into `vendor/xray/<arch>/` and bundles it into the AppImage and `.deb`. Maintainers can refresh the vendor copy directly:

```bash
./scripts/fetch_xray_core.sh
```

Artifacts are written to `dist/`:

- `v2link-client-<version>-linux-<arch>.AppImage`
- `v2link-client_<version>_<arch>.deb`
- `SHA256SUMS`

## Release Process (Maintainers)

Canonical version source: `pyproject.toml` (`[project].version`).

1. Update `pyproject.toml` version.
2. Update `CHANGELOG.md`.
3. Commit changes.
4. Create and push matching tag:

```bash
git tag v<version>
git push origin v<version>
```

5. GitHub Actions workflow `.github/workflows/release.yml` will:
- verify `tag version == pyproject version`
- build AppImage + `.deb` + `SHA256SUMS`
- upload artifacts to GitHub Release
- publish/update signed APT repo to `gh-pages`

## APT Signing Key Setup (Maintainers)

Public key file is committed at `apt/public.key`.

Export matching private key:

```bash
gpg --armor --export-secret-keys "v2link-client APT Repository <apt@v2link-client.local>"
```

GitHub secrets:

- `APT_GPG_PRIVATE_KEY`: ASCII-armored private key
- `APT_GPG_PASSPHRASE`: key passphrase (if protected)

## Usage

1. Paste `vless://` link.
2. Click **Validate & Save**.
3. Click **Start**.
4. Enable **System Proxy** for desktop-wide proxying, or use **Copy manual proxy settings**.

The app resolves Xray-core in this order: custom path from **Xray Settings**, bundled Xray, then system `xray` from `PATH`. Diagnostics and About show the active Xray source, path, and version.

## Traffic Monitor

The Traffic Monitor records local traffic history and shows:

- Dashboard tabs for **Overview**, **Applications**, **Proxy Profiles**, **History**, **Settings**, and **Diagnostics**
- Today upload/download totals
- Current session upload/download and live speed
- This month upload/download totals
- Per saved-profile upload/download totals
- Daily usage aggregation and a lightweight in-app daily usage chart
- Daily history with Today, Last 7 days, Last 30 days, This month, and custom date ranges
- Session history for each selected date, including start/end time, duration, profile, download, upload, total, average speed, and status
- Session drill-down charts for speed or cumulative usage over time
- Advanced **Applications** tab for future per-application tracking
- Settings for detailed sample retention, CSV export, and clearing local traffic history
- Diagnostics for the stats API, helper readiness, and local traffic database

## Proxy/Profile Tracking

Proxy/profile tracking records traffic from Xray's Stats API while the core is running. It works in the normal GUI with no root permission because Xray provides proxy counters through its local API. The app does not use `xray api -reset`, so live labels and history do not fight over counters.

Live counters are polled every 2 seconds, while cumulative history is persisted every 5 seconds through one bounded SQLite writer. Overview work runs at most every 10 seconds and only for its visible tab. History and diagnostics do not query on live ticks. Automatic session charts load and render at most 900 peak-preserving points; detailed samples default to 30-day retention.

The original progressive stutter came from coupling each live callback to synchronous SQLite writes, full dashboard/history refreshes, and increasingly large chart reads. Those paths are now separated and bounded. See [Traffic Monitor internals](docs/traffic-monitor.md) and [runtime performance troubleshooting](docs/runtime-performance-troubleshooting.md).

Bundled Xray-core is enough for proxy/profile tracking in official AppImage, `.deb`, and APT installs. Per-application tracking is separate and still needs the optional helper service described below.

Daily totals are aggregated by sample date and are useful for range summaries. Session totals are grouped by each Start/Stop run, so a connection from 20:00 to 20:30 appears as one session under that date. CSV export supports daily summaries, session summaries, and selected-session samples.

Traffic history is stored locally only in SQLite:

```text
$XDG_DATA_HOME/v2link-client/traffic.sqlite3
```

If `XDG_DATA_HOME` is not set, the app uses the platform default data directory through `platformdirs`, usually `~/.local/share/v2link-client/traffic.sqlite3` on Linux.

Settings are stored at:

```text
$XDG_CONFIG_HOME/v2link-client/traffic_settings.json
```

## Per-Application Tracking

Per-application tracking is advanced and optional. It is separate from normal proxy/profile traffic tracking, which works through Xray's Stats API without root permission. True Linux app attribution needs the optional privileged helper service `v2link-netmon`, because process/executable attribution must happen outside the unprivileged GUI. The GUI never runs as root.

Debian packages install the optional helper and systemd service, but do not enable it automatically:

```bash
sudo systemctl enable --now v2link-netmon
sudo systemctl disable --now v2link-netmon
```

The helper exposes read-only JSON stats over `/run/v2link-client/netmon.sock`. In v0.2.0 this path is prepared/scaffolded and remains optional; if the helper, permissions, or eBPF backend are unavailable, the GUI stays unprivileged and shows a clear unavailable/diagnostic state.

## Privacy

Traffic history never leaves your machine. Proxy/profile stats come from Xray counters. Application traffic tracking records local process names, executable paths, UIDs, and byte counters only. It does not decrypt traffic, inspect packet payloads, read messages, collect tokens/cookies, or upload telemetry anywhere.

## Limitations

Per-application attribution is not perfect when a local proxy is involved. When system proxy is enabled, apps may connect to `127.0.0.1` while Xray performs the encrypted remote connection, so some traffic can appear under `Xray Core / Proxy Tunnel`. Xray is shown separately and is not hidden.

## Troubleshooting Traffic Monitor

- If proxy/profile totals stay at zero, confirm Xray is running and the diagnostics tab shows a configured stats API server.
- If the Applications tab says the helper is unavailable, enable the optional service with `sudo systemctl enable --now v2link-netmon`.
- If the helper is running but eBPF is unavailable, check Traffic Monitor diagnostics for kernel/capability details.
- For growing CPU, memory, logs, or suspected leftover processes, run `./scripts/diagnose_runtime_performance.sh` as your normal user. It prints aggregate sizes and process metadata, never profile URLs, credentials, traffic rows, or process arguments. Exit code `1` means it found a possible stale Xray/stats process to inspect; it never kills anything.
- Closing V2Link stops only the GUI-owned Xray process group and temporary `xray api statsquery` child. The independent system `v2link-netmon.service` may remain running by design.
- Python logs rotate at 2 MiB with five backups. `xray_stdout.log` is bounded to 2 MiB with two backups. Xray access logging is disabled by default; detailed bounded diagnostic logging can be enabled under **Xray Settings**.
- AppImage builds work without the helper and will show the helper-unavailable state.

## Supported Link Scope

Currently implemented:

- `vless://`
- `security=tls` and `security=none`
- transport: `tcp`, `ws`, `grpc`
- optional: `sni`, `fp`, `alpn`, `allowInsecure`, `flow`
- limited `headerType=http` handling for TCP

Not yet implemented:

- `vmess://`, `trojan://`, `ss://`
- REALITY and advanced routing profiles

## Data and Logs

- Saved profiles: `$XDG_CONFIG_HOME/v2link-client/profiles.json` (fallback `~/.config/v2link-client/profiles.json`)
- Preferences/legacy compatibility: `~/.config/v2link-client/profile.json`
- Optional custom Xray path: `$XDG_CONFIG_HOME/v2link-client/xray_settings.json`
- Traffic settings: `$XDG_CONFIG_HOME/v2link-client/traffic_settings.json`
- Traffic database: `$XDG_DATA_HOME/v2link-client/traffic.sqlite3`
- Runtime state and logs: `$XDG_STATE_HOME/v2link-client/` (logs are in `logs/`)

Unset XDG variables use the normal Linux defaults under `~/.config`, `~/.local/share`, and `~/.local/state`. To stop detailed sample growth, turn off proxy/profile history in **Traffic Monitor → Settings**; aggregate display still remains available for the live session.
- Runtime state and generated config: `~/.local/state/v2link-client/`
- Logs: `~/.local/state/v2link-client/logs/`

## Troubleshooting

### Connectivity OFFLINE / TLS EOF errors

Common causes:

- Invalid endpoint or blocked server
- Mismatched `sni` and certificate with strict TLS verification (`allowInsecure=0`)

Actions:

- verify link/server settings
- try `sni` aligned with target host
- inspect logs via **Open logs folder**

### Qt xcb plugin error (`libxcb-cursor.so.0`)

Install missing runtime library:

```bash
sudo apt update
sudo apt install -y libxcb-cursor0
```
