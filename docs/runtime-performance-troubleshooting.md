# Runtime performance and shutdown troubleshooting

Use this guide when the Traffic Monitor becomes less responsive over time, storage or logs grow unexpectedly, proxy settings remain applied, or Xray appears to remain after the GUI exits.

## Safe first check

Run as the same unprivileged user who runs V2Link:

```bash
./scripts/diagnose_runtime_performance.sh
```

The script is read-only. It reports process count and safe `ps` columns (PID, parent/group, elapsed time, CPU, memory, RSS, executable name), database/WAL/log sizes, optional aggregate SQLite counts, and `v2link-netmon.service` state. It deliberately omits command arguments, environment variables, traffic rows, links, credentials, tokens, and profile contents. Missing `sqlite3`, `systemd`, files, and services are handled without requiring root.

Exit code `0` means no stale-process pattern was found. Exit code `1` means a possible Xray or stats-query process exists without a detected GUI. This is a finding, not proof of ownership: inspect it before taking action because a system or separately launched Xray may be legitimate. The script never kills a process or changes proxy settings.

## Expected paths and bounds

Linux defaults are:

- Database: `~/.local/share/v2link-client/traffic.sqlite3` plus temporary `-wal`/`-shm` files.
- Logs: `~/.local/state/v2link-client/logs/`.
- Traffic settings: `~/.config/v2link-client/traffic_settings.json`.
- Xray settings: `~/.config/v2link-client/xray_settings.json`.

`XDG_DATA_HOME`, `XDG_STATE_HOME`, and `XDG_CONFIG_HOME` override those bases. Packaged/sandboxed launchers may therefore show a different safe path.

`app.log` rotates at 2 MiB with five backups. `xray_stdout.log` is capped at 2 MiB with two backups. Access logging is off. Legacy `xray_access.log` and `xray_error.log` are truncated to a safe bound on the next core start and are no longer written by current generated configs.

## Reading cached Diagnostics

Open the Diagnostics tab to refresh expensive aggregate values. Live ticks do not execute count queries. Useful fields include polling interval/in-flight/skips/failures, query and callback timings, persistence queue/write timings, Overview and History refresh duration, chart source/rendered rows, DB/WAL sizes and aggregate counts, GUI-owned Xray/stats PIDs, proxy backend, and netmon state.

Thresholds are:

- Stats query: 500 ms.
- SQLite write: 100 ms.
- Overview refresh: 200 ms.
- History refresh: 500 ms.

One isolated slow value can be normal on a busy machine. Repeated high averages, queue drops, or persistent WAL/log growth are more useful signals.

## Ownership after shutdown

Normal GUI shutdown stops timers, blocks new jobs, invalidates background generations, persists the latest counters, finalises the current session, terminates/reaps the GUI-owned Xray group and temporary stats-query, restores proxy settings owned by that session, and drains the storage writer within bounded waits.

`v2link-netmon.service` is a system service and may remain active. That is expected. The GUI never kills unrelated Xray processes; if the script reports one, compare its parent/group and executable name with your own service or manual launch setup.

## Reducing history work

Automatic charts never load or render more than 900 samples. Detailed retention defaults to 30 days and can be set to 7, 30, 90, or explicitly forever. Turn off proxy/profile history in Traffic Monitor Settings if detailed storage is not required. CSV export remains an explicit background operation rather than a live-refresh task.
