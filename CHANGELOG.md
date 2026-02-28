# Changelog

All notable changes to this project are documented in this file.

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
