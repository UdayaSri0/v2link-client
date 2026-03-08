# System Proxy Regression Root Cause (Ubuntu GNOME/X11)

## Summary
`System Proxy` was treated as a one-time startup action. The app applied GNOME proxy settings once, verified them once, and then assumed they stayed correct for the whole session.

## Why It Looked Unreliable
1. GNOME proxy keys could drift during runtime (`mode` returning to `none`, host/port changes, etc.).
2. The app had no runtime reconciliation loop, so drift was not corrected.
3. Restore/no-proxy behavior depended mostly on snapshot presence, without explicit per-session ownership semantics.
4. `gsettings` commands with `rc=0` but noisy stderr (broken module load warnings) were logged as normal command output, not elevated as warning signals in diagnostics.

## Fix Implemented
1. Added a lightweight runtime audit/reconcile path while Xray is running.
2. Added snapshot ownership metadata (`session_id`, `owner_pid`) and ownership-aware restore behavior.
3. Kept crash recovery, but skipped stale-restore actions when snapshot owner appears to be an active different process.
4. Elevated suspicious `gsettings` stderr with `rc=0` to backend warnings and surfaced them in diagnostics.
5. Expanded diagnostics to separate:
   - desired proxy state
   - actual GNOME state
   - local listener reachability
   - recent traffic flowing signal

## Net Effect
The app now keeps GNOME proxy settings aligned during active sessions, avoids clobbering proxy state from non-owning sessions, and provides diagnostics that distinguish desktop-proxy drift from app-bypass behavior.
