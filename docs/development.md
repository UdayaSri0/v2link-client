# Developer guide

This guide explains how to set up, run, inspect, test, and package `v2link-client` from a source checkout. It also records the runtime rules that are important when changing proxy, traffic-monitor, or shutdown code.

## Requirements

The application targets Linux and Python 3.11 or newer. Development requires:

- Python 3.11+
- `venv` and `pip`
- Git
- Qt's Linux runtime libraries, especially `libxcb-cursor.so.0`
- Xray-core, either from `vendor/xray/<arch>/`, a custom path, or `PATH`

On Debian or Ubuntu, the minimum source-development setup is typically:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git libxcb-cursor0
```

Rust and Cargo are only required when working on the optional `v2link-netmon` helper or building Debian release packages.

## Clone and run quickly

```bash
git clone https://github.com/UdayaSri0/v2link-client.git
cd v2link-client
./scripts/dev_run.sh
```

`dev_run.sh` creates `.venv` when needed, installs `requirements.txt`, checks the important Qt xcb library, adds `src/` to `PYTHONPATH`, and starts `v2link_client.main`.

Do not run the GUI with `sudo`. The GUI, profiles, traffic database, logs, and system-proxy snapshot are designed to belong to the desktop user. The optional netmon helper is the separate privileged component.

## Manual development environment

Use this setup when you want direct control over the environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pip install -e .
python -m v2link_client.main
```

An editable install makes `v2link_client` importable without manually setting `PYTHONPATH`. Without an editable install, run from the repository with:

```bash
PYTHONPATH=src python -m v2link_client.main
```

For a programmatic entry point:

```python
from v2link_client.main import main

raise SystemExit(main())
```

Internal modules are importable for tests and development, but they are not currently a stable third-party Python API.

## Xray-core for source runs

The application resolves Xray in this order:

1. Custom executable selected in **Xray Settings**.
2. Bundled executable under `vendor/xray/<arch>/` or `V2LINK_BUNDLED_XRAY_DIR`.
3. A system `xray` executable from `PATH`.

To fetch the pinned release and geo assets used by packaging:

```bash
./scripts/fetch_xray_core.sh
```

Never replace the pinned version or checksums without reviewing Xray release notes and updating the associated tests and third-party notices.

## Repository map

```text
src/v2link_client/
├── main.py                 Application entry point
├── core/                   Config, process, proxy, storage, stats, diagnostics
├── platform/               GNOME, KDE, and NetworkManager integration
└── ui/                     PyQt windows and Traffic Monitor widgets

tests/                      Python unit, UI, lifecycle, and performance tests
scripts/                    Development, diagnostics, and packaging commands
netmon/                     Optional Rust per-application helper workspace
packaging/                  Desktop, AppImage, Debian, and systemd assets
vendor/xray/                Pinned Xray binaries, geo data, version, and license
docs/                       Architecture, operations, releases, and troubleshooting
```

The main runtime flow is:

```text
MainWindow
  → validates/builds an Xray JSON configuration
  → starts an app-owned Xray process group
  → polls cumulative Xray stats in a background worker
  → updates live UI state in memory
  → queues periodic cumulative samples to the SQLite writer
  → refreshes only the visible Traffic Monitor section
```

## Important runtime rules

Keep these invariants when modifying the application:

- The Qt GUI thread must not perform network calls, long subprocess calls, large database reads, exports, or growing chart work.
- Only one stats query may be active. Every app-owned subprocess must be identifiable, bounded by a timeout, and reaped.
- Live stats callbacks update memory and labels only. SQLite persistence runs through the bounded storage worker every five seconds.
- Automatic charts return and render no more than 900 points. Full sample reads are reserved for explicit exports.
- Expensive diagnostics run only when requested or visible, never on each live tick.
- Shutdown is idempotent: stop timers, invalidate generations, finalize traffic, stop owned process groups, restore owned proxy state, and drain storage without touching deleted widgets.
- Never kill an unrelated system Xray. Never stop `v2link-netmon.service` as part of normal GUI shutdown.
- Xray access logging stays disabled by default. Detailed diagnostic output must remain inside the bounded stdout log.
- Diagnostics and logs must not expose profile URLs, UUIDs, credentials, tokens, or private configuration contents.

See [Traffic Monitor internals](traffic-monitor.md) and [runtime performance troubleshooting](runtime-performance-troubleshooting.md) for the detailed cadence and ownership model.

## Local data and isolated runs

Normal Linux paths are:

```text
~/.config/v2link-client/       Preferences, profiles, Xray/traffic settings
~/.local/share/v2link-client/  traffic.sqlite3
~/.local/state/v2link-client/  Generated runtime config, proxy snapshot, logs
```

The corresponding `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, and `XDG_STATE_HOME` variables override these bases. Use temporary XDG directories when testing migrations or startup so personal profiles and history are not touched:

```bash
tmp_dir="$(mktemp -d)"
XDG_CONFIG_HOME="$tmp_dir/config" \
XDG_DATA_HOME="$tmp_dir/data" \
XDG_STATE_HOME="$tmp_dir/state" \
PYTHONPATH=src \
python -m v2link_client.main
rm -rf "$tmp_dir"
```

Use only test profiles and authorized traffic. Never commit real share links, profile databases, generated Xray configs, logs, or proxy snapshots.

## Tests and checks

Run the complete Python validation used by the project:

```bash
python -m compileall src
python -m pytest -q
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

Run a focused test while developing:

```bash
python -m pytest -q tests/test_process_manager.py
python -m pytest -q tests/test_traffic_monitor_hot_path.py
```

For the optional Rust workspace:

```bash
cd netmon
cargo test --workspace
cd ..
```

Validate shell syntax and use ShellCheck when installed:

```bash
bash -n scripts/*.sh
shellcheck scripts/*.sh
```

The repository currently has no configured Python formatter, linter, or type checker. Match the surrounding code style, keep imports explicit, and run the full tests before submitting changes.

## Traffic database changes

`TrafficStore` owns SQLite schema and migrations. When changing storage:

1. Add a forward-only migration instead of rewriting or deleting existing migrations.
2. Keep existing databases readable without deleting traffic history.
3. Use the storage worker for recurring writes.
4. Bound automatic queries and UI result sizes.
5. Add compatibility, retention, failure-recovery, and long-session tests.

Do not inspect or modify a developer's real traffic database during automated tests. Pytest's `tmp_path` fixtures should own test databases.

## Building packages

Build the Python onedir bundle:

```bash
./scripts/build_pyinstaller.sh
```

Build individual release formats:

```bash
./scripts/build_appimage.sh
./scripts/build_deb.sh
```

Build the complete release set and checksums:

```bash
./scripts/build_release.sh
```

The Debian build also requires Cargo and `dpkg-deb`. The AppImage build downloads `appimagetool` into the ignored `tools/` directory when it is unavailable. Generated outputs belong in ignored `build/`, `dist/`, `tools/`, and `netmon/target/` directories and must not be committed.

Before publishing, verify bundled Xray discovery, source startup, AppImage startup, Debian payload contents, database compatibility, proxy apply/restore, and that no app-owned Xray or stats-query process remains after shutdown.

## Runtime diagnostics

For CPU, memory, database, log-growth, service, or stale-process investigation, run:

```bash
./scripts/diagnose_runtime_performance.sh
```

It is read-only and does not require root. Exit code `1` reports a possible stale-process finding; it does not prove ownership and the script never kills anything.

## Common development problems

### `No module named v2link_client`

Install the project in editable mode or include `src` on `PYTHONPATH`:

```bash
python -m pip install -e .
# or
PYTHONPATH=src python -m v2link_client.main
```

### Qt cannot load the xcb platform plugin

Install `libxcb-cursor0`, then rerun `./scripts/dev_run.sh`. Headless tests should set `QT_QPA_PLATFORM=offscreen`.

### Xray-core was not found

Run `./scripts/fetch_xray_core.sh`, install Xray on `PATH`, or select a valid executable in **Xray Settings**.

### A test leaves processes behind

Use real short-lived helper scripts in a temporary directory, launch them in private sessions, and exercise both normal TERM and forced KILL paths. Do not use broad `pkill xray` cleanup because that can terminate unrelated processes.

### The GUI becomes slower as history grows

Check that the change did not add database reads, table refreshes, diagnostics, or chart reconstruction to the live stats callback. Run the long-session tests and the runtime diagnostic script.

## Contribution checklist

- Keep changes scoped and preserve unrelated working-tree edits.
- Add regression tests for behavior changes and failure paths.
- Use temporary XDG directories and synthetic profiles/data.
- Verify normal and offscreen test suites.
- Test graceful and forced process shutdown when lifecycle code changes.
- Update README, CHANGELOG, or the relevant document for user-visible behavior.
- Remove generated databases, logs, package files, profiling output, and build artifacts before committing.
- Review the complete diff for credentials, links, tokens, debug prints, and private paths.
