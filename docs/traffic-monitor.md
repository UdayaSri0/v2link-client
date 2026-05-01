# Traffic Monitor

The Traffic Monitor records historical proxy usage from Xray's Stats API. It also includes the data model, UI, settings, diagnostics, and client API needed for future per-application tracking.

Per-application tracking is marked **Advanced / Optional / Requires helper service**. The privileged helper itself is not implemented in this phase.

## What It Tracks

- Total proxy upload and download over time
- Current session upload and download
- Per saved-profile upload and download totals
- Daily totals
- 7-day and 30-day history summaries
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

Proxy/profile tracking uses Xray's Stats API. It measures traffic that flows through the active proxy/profile and can run entirely inside the normal unprivileged GUI.

True per-application tracking on Linux requires process/executable attribution. That work belongs in a separate optional helper service, planned as:

```text
v2link-netmon
```

The helper is expected to communicate with the GUI over a Unix domain socket or localhost API. The GUI never runs as root.

Until the helper exists and is enabled, the Applications tab shows a clean unavailable state:

```text
Per-application tracking requires the optional v2link-netmon helper service. Proxy/profile tracking is still active.
```

## Privacy

Traffic history stays on the local machine. v2link-client does not upload traffic history or profile usage history to any external service.

Application traffic tracking records local process names, executable paths, and byte counters. It does not decrypt content, inspect messages, or upload data anywhere. All history is stored locally on this device.

## Limitation

Per-application attribution is not fully available in this phase. If multiple applications use the active local proxy, their traffic may appear together under the active proxy profile, and Xray may appear as the main network user until the optional helper provides process attribution.
