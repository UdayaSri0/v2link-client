# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

### Changed

- Migrated legacy VLESS `allowInsecure` imports to normal secure certificate verification with a compatibility warning, and added strict support for provider-supplied `pcs` certificate pins and `vcn` verification names.
- Split netmon installation, daemon and backend states; AppImage now identifies the separately installed helper requirement, while reachable placeholder daemons report non-operational status explicitly.
- Restricted the optional Debian helper to a dedicated non-login account, group-only socket and capability-free systemd sandbox; service activation remains administrator-controlled.

### Fixed

- Stopped generating the Xray-core 26.3.27-removed `allowInsecure` field, invalidated stale saved-profile validation when the config schema or selected Xray identity changes, and sanitized Xray validation errors before displaying them.
- Corrected Debian helper lifecycle handling and extracted-artifact verification without enabling or initially starting the opt-in service.

## [0.2.3] - 2026-07-29

### Changed
- Prepared a corrective release from the current default branch using the guarded manual release workflow.

### Fixed
- Advanced the canonical application and package version so corrected artifacts can be built and verified without reusing or moving the existing v0.2.2 tag.

## [0.2.2] - 2026-07-29

### Added
- Added a canonical Xray release manifest, verification-only vendor checks, offline GUI self-test, and extracted AppImage/Debian artifact verification.

### Changed
- Source startup bootstraps the pinned official Xray release unless `V2LINK_SKIP_XRAY_FETCH=1`.
- All Xray child commands now use a clean host environment with `XRAY_LOCATION_ASSET` derived from the selected executable.
- Official release artifacts currently target x86-64; ARM64 source discovery remains supported pending native package CI.

### Fixed
- Prevented source discovery from selecting an executable for the wrong CPU architecture.
- Made Xray acquisition checksum-first, retrying, version-validated, and staged so a failed refresh cannot leave a partial vendor directory.

## [0.2.1] - 2026-07-14

### Added
- Added a bounded traffic-storage worker for recurring sample writes, retention cleanup, and session finalisation outside the GUI thread.
- Added bounded aggregate and downsampled query paths for long-session Traffic Monitor views.

### Changed
- Live stats callbacks now update in-memory counters and labels only; History, Applications, Profiles, and Diagnostics refresh independently when needed.
- Xray Stats API polling now permits at most one in-flight stats-query child and ignores late results from invalidated generations.
- Traffic history sections cache unchanged results, completed session details are reused, and proxy drift reconciliation runs in the background audit worker.

### Fixed
- Hardened application shutdown into an ordered, idempotent flow that stops timers, invalidates late callbacks, persists final counters, finalises the active session, restores session-owned proxy state, and drains storage within bounded waits.
- GUI-owned Xray and temporary stats-query children now run in private process groups and are reaped with bounded TERM-to-KILL escalation without targeting unrelated system Xray or `v2link-netmon.service`.
- Detailed-sample retention and cleanup now preserve daily, session, and profile summaries while safely reusing SQLite connections.
- Xray access logging is disabled by default, `xray_stdout.log` is bounded to 2 MiB with two backups, and detailed bounded diagnostics are opt-in.

### Performance
- Automatic traffic charts use peak-preserving downsampling and never query or render more than 900 points.
- Long-session history tables avoid full sample scans and reuse unchanged results.
- Recurring stats-query logging and live refresh work are reduced to keep CPU, memory, database, and log growth bounded during long sessions.

### Diagnostics
- Added cached performance diagnostics for polling, callbacks, storage, refreshes, chart bounds, database/WAL sizes, aggregate counts, owned PIDs, proxy backend, and netmon state without exposing private profile data.
- Added `scripts/diagnose_runtime_performance.sh`, a read-only, non-root inspection tool for process, resource, database, log, and service state.

### Testing
- Added long-session regression coverage for the Traffic Monitor hot path, bounded storage, retention, connection reuse, charts, process ownership, Stats API polling, and repeated shutdown.
- Added packaging-script, logging, diagnostics, Xray configuration, and bundled-Xray locator regression coverage.

### Documentation
- Documented source development, bounded Traffic Monitor operations, runtime performance troubleshooting, logging limits, diagnostics privacy, and lifecycle ownership rules.

## [0.2.0] - 2026-05-26

### Added
- Added a Traffic Monitor backed by local SQLite storage for proxy/session/profile upload and download history.
- Added daily usage aggregation, profile usage totals, CSV export support, and a lightweight in-app daily usage chart.
- Added session-level Traffic Monitor history with date drill-down, session detail panels, speed/cumulative sample charts, and session status reporting for completed, active, crashed, or unknown sessions.
- Added CSV export modes for daily summaries, session summaries, and selected session samples.
- Added traffic diagnostics for the SQLite DB path/access, active proxy session ID, stats API configuration, last stats query, and last traffic-store error.
- Added per-application tracking readiness: app traffic tables, data classes, disabled/mock `v2link-netmon` client abstraction, Applications tab, settings, and diagnostics.
- Added the optional `v2link-netmon` Rust helper scaffold with Unix socket JSON API, process identity resolver, SQLite app-usage schema, systemd service packaging, and graceful eBPF-unavailable diagnostics.

### Traffic Monitor
- Added persistent proxy/profile traffic history.
- Added daily and monthly usage summaries.
- Added a Traffic Monitor dashboard with Overview, Applications, Proxy Profiles, History, Settings, and Diagnostics tabs.
- Improved the History tab with range controls, summary cards, stacked daily download/upload bars, daily rows, per-date sessions, and selected-session sample charts.
- Added optional per-application tracking preparation and `v2link-netmon` helper integration.
- Added privacy-focused local-only storage and clear helper/root separation.
- Added diagnostics for Xray stats, the traffic database, app-tracking helper state, and kernel/eBPF support.

### Notes
- Traffic history is local only at `$XDG_DATA_HOME/v2link-client/traffic.sqlite3` (or the platform default data directory).
- Per-application tracking remains advanced/optional; the GUI does not run as root, and the helper reports unavailable when eBPF support or permissions are insufficient.
- This phase tracks proxy/profile usage via Xray Stats API and prepares for, but does not yet provide, full per-application attribution.

## [0.1.9.0.5] - 2026-03-25

### Changed
- Packaged builds now launch host-system tools such as `gsettings` and `xray` with a sanitized native environment, so Debian-installed sessions no longer inherit PyInstaller runtime library/plugin paths into child processes.
- Diagnostics now report runtime packaging mode, executable path, clean-host subprocess mode, exact `gsettings` command details, and the proxied HTTP/HTTPS probe result used for health reporting.
- Runtime builds now bundle and apply the shipped application icon so source runs, AppImage, and Debian packages share the same launcher/window icon.

### Fixed
- Debian-installed runs now preserve system-proxy snapshot creation/restore and GNOME proxy application under packaged execution, matching source-run behavior more closely.
- Xray validation, startup, and traffic-stat commands now use the same clean host subprocess environment as GNOME/system integration calls.
- Replaced the placeholder package icon with the provided application artwork.

## [0.1.9.0.4] - 2026-03-11

### Added
- GitHub release update checks in-app (`Check for Updates…`) with release asset detection for AppImage and `.deb`.
- Runtime system-proxy drift auditing and auto-reapply flow during active sessions.
- Snapshot ownership metadata for safer system-proxy restore behavior across concurrent/stale sessions.
- Saved-profile validation persistence metadata (`validated`, `validated_at`, `validation_fingerprint`) with backward-compatible profile loading.

### Changed
- Main window Help section now includes dedicated `Check Updates` and `About` buttons while preserving existing Help menu actions.
- About dialog metadata was refreshed with current version, repository URL, and current feature highlights.
- Release tooling now resolves version from `pyproject.toml` by default and exports a single build version to all packaging steps.
- GitHub release workflow now verifies pushed tag version matches `pyproject.toml` before building artifacts.

### Fixed
- Saved profile validation now survives restart when connection-defining profile data is unchanged.
- Validation invalidation now only occurs when connection data changes; metadata edits (for example, profile name/notes) no longer force revalidation.
- Long validation/status hints no longer force horizontal window growth; hint area remains width-stable with wrapping and tooltip fallback.
- Hardened GNOME System Proxy lifecycle by adding runtime drift audits/reconciliation while Xray is running, so proxy mode/host/port are auto-corrected on mismatch instead of relying on one-time startup apply.
- Added session ownership metadata to system proxy snapshots and ownership-aware restore paths to avoid false restore/no-proxy actions from non-owning sessions, while keeping crash recovery.
- Improved diagnostics to report proxy backend, desired vs actual GNOME proxy state, local HTTP/SOCKS listener reachability, recent Xray traffic signal, last auto-reapply reason/time, and backend warning signals from `gsettings`/Gio stderr.

## [0.8.2] - 2026-02-28

### Added
- Saved Profiles for VPN URLs, including support for multiple stored share links.
- Default profile auto-load on startup.
- Profile Manager dialog with add, edit, delete, duplicate, favorite toggle, and set-default actions.

### Improved
- Validate & Save flow now handles existing URL matches with update-or-save-new choices.
- URL saving UX now prompts for profile details and supports in-dialog validation.

### Notes
- Profiles are persisted at `$XDG_CONFIG_HOME/v2link-client/profiles.json` (fallback: `~/.config/v2link-client/profiles.json`).
- Profile writes are atomic (`temp file + os.replace`) and use user-only permissions (`0600` on Linux/posix).
