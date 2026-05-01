# Traffic Monitor

The Traffic Monitor records historical proxy usage from Xray's Stats API. It also includes the data model, UI, settings, diagnostics, and client API needed for future per-application tracking.

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

Optional privileged system service
  v2link-netmon
    |-- Unix socket: /run/v2link-client/netmon.sock
    |-- process identity from /proc
    |-- eBPF backend interface with graceful unsupported state
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

The GUI never runs as root. Debian packages install a systemd service but do not enable it automatically. AppImage builds do not install or enable a systemd service, so they will show the helper as not installed/enabled while proxy/profile tracking continues to work through bundled Xray.

Enable the helper:

```bash
sudo systemctl enable --now v2link-netmon
```

Disable the helper:

```bash
sudo systemctl disable --now v2link-netmon
```

The current helper includes the daemon API, SQLite storage, process identity resolver, systemd packaging, and an eBPF backend interface. If eBPF support or permissions are unavailable, it reports that clearly and the GUI falls back to the clean unavailable state.

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
- **Applications tab unavailable:** the optional helper is not installed, not enabled, or not reachable at `/run/v2link-client/netmon.sock`.
- **Permission/capability warning:** the helper may not have enough privilege or kernel support for eBPF accounting. The GUI remains safe and unprivileged.
- **AppImage:** AppImage builds include bundled Xray for proxy/profile stats, but they do not install or enable the privileged helper; install the Debian/APT package to use per-app tracking.
