# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- Help menu action `Check for Updates…` with asynchronous GitHub Releases lookup, version comparison, and update dialogs with open/copy download actions.

### Fixed
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
