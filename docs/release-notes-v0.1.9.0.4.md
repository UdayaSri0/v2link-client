# v2link-client v0.1.9.0.4

This release focuses on profile-validation persistence, runtime proxy reliability, and release/packaging consistency.

## Highlights

- Validated saved profiles now persist correctly across app restarts.
- Validation is invalidated only when connection-defining profile data changes.
- Runtime system-proxy drift detection and auto-reconciliation were improved.
- App release workflow now enforces `tag version == pyproject version`.

## What's New

- Added in-app update checks against GitHub Releases with AppImage/`.deb` asset detection.
- Added session ownership metadata for safer system-proxy restore behavior.
- Added richer diagnostics for desired vs actual proxy state and backend warnings.

## Packaging

- AppImage artifact: `v2link-client-0.1.9.0.4-linux-<arch>.AppImage`
- Debian artifact: `v2link-client_0.1.9.0.4_<arch>.deb`
- Checksums: `SHA256SUMS`

## Fixes

- Fixed repeated revalidation prompts for unchanged saved profiles.
- Fixed validation reset behavior for metadata-only profile edits.
- Fixed UI width instability from long validation/status hints.
- Refined Help/About placement with cleaner in-window Help actions.

## Notes

- Canonical project version source is `pyproject.toml`.
- Release workflow fails early if the pushed tag does not match `pyproject.toml` version.

## Full Changelog

See `CHANGELOG.md` for detailed history.
