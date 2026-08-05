---
type: "query"
date: "2026-08-05T18:14:58.942063+00:00"
question: "Why does MainWindow bridge almost every major subsystem?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["MainWindow", "SystemProxyManager", "ProfileStore", "TrafficStore", "TrafficMonitorWidget", "NetmonClient", "XrayProcessManager", "DiagnosticsWidget", "LatestErrorStore", "TrafficStorageWorker"]
---

# Q: Why does MainWindow bridge almost every major subsystem?

## Answer

Expanded from original query via graph vocabulary: [main, window, proxy, profile, traffic, diagnostics, netmon, health, xray, update, error, store]. MainWindow is the UI composition root and runtime orchestrator. The graph records 141 direct edges: 107 extracted method-ownership edges, 4 other extracted structural edges, and 30 inferred uses edges. Its methods are distributed across runtime error handling, diagnostics polling, link validation, preferences, health auditing, profiles, proxy control, traffic storage, and Xray lifecycle communities. Extracted paths show main() calls MainWindow; its constructor calls NetmonClient, XrayProcessManager, ProfileStore, and SystemProxyManager; validation methods call parse_link, build_xray_config, load_xray_settings, and validate_xray_config; runtime diagnostics call active_stats_query_pid, xray_asset_status, detect_runtime_kind, and sanitize_sensitive_text. The bridge is therefore real, although its degree is inflated by method ownership and the 30 inferred class-to-import uses edges.

## Outcome

- Signal: useful

## Source Nodes

- MainWindow
- SystemProxyManager
- ProfileStore
- TrafficStore
- TrafficMonitorWidget
- NetmonClient
- XrayProcessManager
- DiagnosticsWidget
- LatestErrorStore
- TrafficStorageWorker
- TrafficStats