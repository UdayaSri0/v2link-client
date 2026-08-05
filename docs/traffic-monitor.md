# Traffic Monitor

The Traffic Monitor records historical proxy usage from Xray's Stats API. It also includes the data model, UI, settings, diagnostics, and client API needed for future per-application tracking.

## Bounded live-update architecture

The GUI intentionally separates four cadences:

- Xray cumulative counters: every 2 seconds, with at most one `statsquery` child at once.
- SQLite persistence: every 5 seconds through one bounded, coalescing writer queue.
- Visible Overview refresh: every 10 seconds.
- Visible Diagnostics refresh: every 30 seconds or when manually opened.

A live result updates only in-memory labels and the current sample. It does not refresh History, Applications, Profiles, or Diagnostics. Automatic session charts query and render no more than 900 peak-preserving samples. Completed details are cached, history tables reuse unchanged data, and detailed rows default to 30-day retention. Daily aggregates default to 365 days.

Slow-operation thresholds shown in diagnostics are 500 ms for a stats query, 100 ms for a database write, 200 ms for Overview, and 500 ms for History. They are diagnostic thresholds, not extra polling work.

## Shutdown ownership

Xray-core and each temporary `xray api statsquery` are launched in private process sessions. Stop and application shutdown invalidate pending callbacks, persist the latest cumulative counters, end the active traffic session, send TERM to the owned group, escalate to KILL after a bounded wait, and reap it. Repeating shutdown is safe.

The system `v2link-netmon.service` is independent. Closing the GUI does not stop, restart, or kill it. Diagnostics label GUI-owned Xray, temporary stats-query, and netmon state separately.

## Logs and privacy

Xray access logging is disabled by default because it grows per request and can expose destinations. Xray warnings go to a bounded `xray_stdout.log` (2 MiB, two backups). The optional detailed mode in Xray Settings changes that bounded stream to debug level without enabling access logs. Python `app.log` rotates at 2 MiB with five backups.

Cached performance diagnostics contain timings, queue depth, aggregate database counts/sizes, rendered point counts, and owned PIDs. They exclude session UUIDs, links, credentials, tokens, and private profile contents. Database counts and file sizes are refreshed only when Diagnostics is visible or manually opened—not on live ticks.

The main Diagnostics panel displays the same sanitized, size-bounded report used by **Copy diagnostics report** and **Save diagnostics report**. **Copy latest error** exports only the newest active structured error. The helper card's **Copy diagnostics** action uses the same privacy boundary and includes installation, daemon, backend, operational, reason, service, socket, kernel, response/error, and remediation fields without process rows. Review any report before sharing it publicly.

Per-application tracking is marked **Advanced / Optional / Requires helper service**. The optional helper is `v2link-netmon`.

## Architecture

```text
Normal desktop user
  v2link-client (Python/PyQt6 GUI, never root)
    |-- reads Xray Stats API through local xray CLI calls
    |-- writes local SQLite traffic history
    |-- optionally reads app stats from Unix socket
    |
    +--> Xray-core
          |-- local SOCKS/HTTP proxy listeners
          |-- local Stats API when proxy is running

Optional system service
  v2link-netmon
    |-- Unix socket: /run/v2link-client/netmon.sock
    |-- process identity from /proc
    |-- explicit non-operational placeholder backend in v0.2.4
    |-- local SQLite app usage storage
```

## What It Tracks

- Total proxy upload and download over time
- Current session upload and download
- Per saved-profile upload and download totals
- Daily totals
- Daily history for Today, Last 7 days, Last 30 days, This month, and custom date ranges
- Individual proxy sessions for a selected date
- Per-session samples for speed and cumulative usage charts
- Readiness state for future per-application tracking

## Storage

Traffic history is stored locally in SQLite:

```text
$XDG_DATA_HOME/v2link-client/traffic.sqlite3
```

When `XDG_DATA_HOME` is not set, v2link-client uses the platform default data directory through `platformdirs`, usually:

```text
~/.local/share/v2link-client/traffic.sqlite3
```

The database is created automatically. No root permission is required.

Traffic Monitor settings are stored at:

```text
$XDG_CONFIG_HOME/v2link-client/traffic_settings.json
```

## Proxy Tracking vs App Tracking

Proxy/profile tracking uses Xray's Stats API. It measures traffic that flows through the active proxy/profile and can run entirely inside the normal unprivileged GUI. The bundled Xray-core included in official AppImage, `.deb`, and APT builds is enough for this proxy/profile tracking; users do not need to install a separate system Xray package for normal use.

The app queries Xray counters without `-reset`, computes safe deltas locally, and treats counter decreases as resets with a zero delta. Xray restarts create separate sessions.

## Daily History vs Session History

Daily history aggregates all proxy/profile traffic samples by date. It is useful for totals, trends, and comparing days.

Session history groups traffic by each Start/Stop run. For example, if v2link-client starts at 20:00 and stops at 20:30, the History tab shows one session for that date with:

- Start time
- End time
- Duration
- Profile name
- Download
- Upload
- Total
- Average speed
- Status

Selecting a date loads all sessions that started on that date. Selecting a session shows details such as peak speed, API server, SOCKS/HTTP ports, and a chart of samples from that session.

Unfinished sessions are preserved. If the app is restarted after an unexpected stop, sessions without an end time are shown as `crashed` or `unknown` rather than being silently dropped.

## CSV Export

History export supports three CSV shapes:

- Daily summary: `v2link-traffic-daily-YYYY-MM-DD_to_YYYY-MM-DD.csv`
- Session summary: `v2link-traffic-sessions-YYYY-MM-DD_to_YYYY-MM-DD.csv`
- Selected session samples: `v2link-traffic-session-SESSION_ID.csv`

Daily summaries include date totals and session counts. Session summaries include start/end time, duration, profile, totals, average speeds, and status. Session sample exports include raw Xray counters, deltas, and calculated upload/download speeds.

## Retention

Detailed session samples can be kept for 7 days, 30 days, 90 days, or forever. Cleanup only removes old detailed sample rows. It does not delete session summaries, daily totals, or profile totals.

True per-application tracking on Linux still requires process/executable attribution. That work belongs in a separate optional helper service:

```text
v2link-netmon
```

The helper communicates with the GUI over a read-only Unix domain socket:

```text
/run/v2link-client/netmon.sock
```

The GUI never runs as root. Debian packages install a dedicated `v2link-netmon` system account, helper and systemd service, but do not enable or initially start it and do not add desktop users to its group. AppImage builds do not contain or install the helper; they report that an external system helper is required while proxy/profile tracking continues through bundled Xray.

Administrator-controlled opt-in:

```bash
sudo usermod -aG v2link-netmon "$USER"
sudo systemctl enable --now v2link-netmon
```

Log out and back in after joining the group. The socket uses mode `0660`; it is not world-accessible.

Disable the helper:

```bash
sudo systemctl disable --now v2link-netmon
```

The v0.2.4 daemon API explicitly reports `backend-not-implemented`, `operational=false`, and no counters. A reachable daemon is not equivalent to operational attribution. Prompt 3B must implement the production backend and reassess privileges; v0.2.4 grants no Linux capabilities to the placeholder.

Until the helper exists and is enabled, the Applications tab shows a clean unavailable state:

```text
Per-application tracking requires the optional v2link-netmon helper service. Proxy/profile tracking is still active.
```

## Privacy

Traffic history stays on the local machine. v2link-client does not upload traffic history or profile usage history to any external service.

Application traffic tracking records local process names, executable paths, UIDs, and byte counters only. It does not decrypt traffic, inspect packet payloads, read DNS contents, inspect messages, collect tokens/cookies, or upload data anywhere. All history is stored locally on this device.

## Limitation

Per-application attribution is not fully available in this phase. If multiple applications use the active local proxy, their traffic may appear together under the active proxy profile, and Xray may appear as the main network user until the optional helper provides process attribution.

When Xray is detected by the helper, it is labeled as:

```text
Xray Core / Proxy Tunnel
```

It is not hidden, because Xray really performs the encrypted remote connection when the proxy is active.

## Troubleshooting

- **No proxy/profile traffic:** start Xray from the GUI and check Diagnostics for the Xray stats API server and last query result.
- **Progressive slowdown or suspected process leak:** run `./scripts/diagnose_runtime_performance.sh` without root, then compare owned PIDs, CPU/RSS, DB/WAL sizes, aggregate row counts, and bounded log sizes. See [runtime performance troubleshooting](runtime-performance-troubleshooting.md).
- **Detailed history is not wanted:** disable proxy/profile history under Settings. Retention can otherwise be limited to 7, 30, or 90 days (or kept forever explicitly).
- **Helper not installed:** install/provision the Debian system helper; normal proxy/profile tracking is unaffected.
- **Installed but inactive/socket missing:** opt in to the service explicitly; installation never starts it automatically.
- **Permission denied:** join the `v2link-netmon` group and log out/in; never run the GUI as root.
- **Backend not implemented:** expected in v0.2.4; no per-app counters are available or fabricated.
- **Copy helper diagnostics:** the copied text labels `backend-not-implemented` as non-operational; this informational product state is not promoted to the application's latest error.
- **AppImage:** the AppImage is not damaged. It includes bundled Xray proxy/profile stats but requires a separately installed system helper for optional app attribution.
