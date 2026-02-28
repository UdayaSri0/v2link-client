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
- Save multiple VPN URLs as named profiles (favorite/default supported)
- Profile dropdown + manager dialog (add/edit/delete/duplicate/set default)
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
- **Xray-core** available in your `PATH` (`xray version` should work)

## Installation (download release)

1) Open GitHub Releases and download the latest `*.AppImage` file.

2) Make it executable and run it:

```bash
chmod +x v2link-client-*.AppImage
./v2link-client-*.AppImage
```

3) (Optional) Add launcher entry:

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

Replace `YOUR_USER` with your Linux username.

If `xray version` fails, install Xray-core first and re-run the app.

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

## Release process (maintainers)

Build artifacts locally:

```bash
./scripts/build_release.sh
```

Outputs are written to `dist/`:
- `v2link-client-<version>-linux-<arch>.AppImage`
- `SHA256SUMS`

Publish on GitHub:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Tag pushes matching `v*` trigger `.github/workflows/release.yml`, which builds the AppImage and uploads assets to the GitHub Release automatically.

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

## Saved Profiles (URLs)

Saved Profiles let you store multiple VPN share links and quickly reuse them.

- Create a profile:
  - Paste a URL, click **Validate & Save**, then enter a profile name and save.
  - If the URL already exists, the app offers **Update Profile** or **Save as New**.
- Switch profiles:
  - Use the **Profile** dropdown to load any saved profile URL into the input field.
- Manage profiles:
  - Click **Manage** next to the profile dropdown.
  - From Profile Manager you can Add/Edit/Delete profiles, Set Default, Duplicate, and toggle Favorite.
- Default profile:
  - The default profile is auto-selected on app start and its URL is loaded automatically.
- Storage location:
  - `profiles.json` is stored at `$XDG_CONFIG_HOME/v2link-client/profiles.json`.
  - If `XDG_CONFIG_HOME` is unset, fallback is `~/.config/v2link-client/profiles.json`.
- Migration:
  - On first launch after upgrading, an older single saved URL (from `profile.json`) is auto-imported as an `Imported Profile` and set as default.

## Supported link subset (today)

`vless://` with:
- `security=tls` or `security=none`
- transports: `type=tcp`, `type=ws`, `type=grpc`
- optional: `sni`, `fp` (fingerprint), `alpn`, `allowInsecure`, `flow`
- TCP `headerType=none` (and limited support for `headerType=http`)

Not supported yet:
- `vmess://`, `trojan://`, `ss://`
- REALITY, advanced XTLS options, complex routing rules

## Logs & data locations

- Saved profiles: `$XDG_CONFIG_HOME/v2link-client/profiles.json` (fallback `~/.config/v2link-client/profiles.json`)
- UI preferences + legacy compatibility: `~/.config/v2link-client/profile.json`
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

### Qt fails with "Could not load the Qt platform plugin xcb"

If startup fails with messages mentioning `xcb` and `libxcb-cursor`, install the missing runtime dependency:

```bash
sudo apt update
sudo apt install -y libxcb-cursor0
```

Then run the app again.

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
