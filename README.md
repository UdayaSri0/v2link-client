# v2link-client

Linux desktop client for V2Ray-style links, built with Python 3.11+ and PyQt6, powered by Xray-core.

Current release target: **v0.1.9.0.4**

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
- Diagnostics panel with runtime proxy state and log access
- Built-in update check against GitHub Releases
- Light/Dark theme

## Runtime Requirements

- Linux desktop environment (GNOME/KDE/etc.)
- `xray` available in `PATH`

Quick check:

```bash
xray version
```

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
