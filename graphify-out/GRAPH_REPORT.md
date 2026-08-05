# Graph Report - .  (2026-08-05)

## Corpus Check
- 126 files · ~272,893 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1418 nodes · 3795 edges · 80 communities (61 shown, 19 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 327 edges (avg confidence: 0.6)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- System Proxy Management
- Profile Storage and Editing
- Netmon Rust Service
- Diagnostics UI and Sanitization
- Netmon Client Integration
- Versioning and Health Checks
- Link Parsing and Configuration
- Diagnostics Subprocess Environment
- Traffic Monitor Refresh UI
- Main Window Orchestration
- Traffic Hot Path Testing
- Xray Discovery and Settings
- Traffic Monitor Components
- Traffic Database Operations
- Chart Theme Rendering
- Traffic Store Queries
- Runtime Error State
- Validation Error UI Tests
- Humanized Session Timestamps
- Traffic Storage Worker
- Update Checking
- Latest Error Formatting
- Latest Error Store Tests
- Linux Process Sampling
- Link Validation and Profiles
- Xray API Errors
- Secure Logging Pipeline
- Traffic Stats Lifecycle
- Xray Process Management
- Session Chart Data
- Project Architecture Documentation
- Traffic UI Layout
- Process Manager Tests
- Network Health Workers
- Traffic History Queries
- Storage Performance Tests
- Application Entry and Assets
- User Preferences and Theme
- Traffic Database Migrations
- Health and Proxy Audits
- TLS Probe Tests
- Traffic UI Integration Tests
- Traffic Monitor Dark UI
- Xray Fetch Script
- Owned Process Termination
- Xray Binary Runtime
- Sanitized Logging Tests
- Application Storage Paths
- Desktop Dark Theme
- Traffic Monitor Light UI
- Debian Package Build
- Xray API Process Tests
- V2 Brand Logo
- Desktop Light Theme
- AppImage Build
- Development Runner
- Runtime Diagnostic Script
- Release Artifact Verification
- Bundled Xray Licensing
- Release Build Orchestration
- CI Workflow Tests
- Debian Postinstall
- Packaged App Icon
- APT Repository Build
- Debian Postremove
- Debian Preremove
- Netmon Build
- PyInstaller Build
- GNOME Proxy Backend
- KDE Proxy Backend
- NetworkManager Proxy Backend
- Graphify Navigation Guidance
- Python Package Metadata

## God Nodes (most connected - your core abstractions)
1. `MainWindow` - 141 edges
2. `TrafficStore` - 112 edges
3. `TrafficMonitorWidget` - 109 edges
4. `sanitize_sensitive_text()` - 66 edges
5. `TrafficStats` - 48 edges
6. `NetmonClient` - 46 edges
7. `SystemProxyManager` - 39 edges
8. `HealthCheckWorker` - 37 edges
9. `parse_link()` - 34 edges
10. `ProfileStore` - 34 edges

## Surprising Connections (you probably didn't know these)
- `_SyntheticProcess` --uses--> `PortInUseError`  [INFERRED]
  tests/test_process_manager.py → src/v2link_client/core/errors.py
- `test_large_nonmatching_unicode_input_has_bounded_runtime()` --calls--> `sanitize_sensitive_text()`  [EXTRACTED]
  tests/test_logging_setup.py → src/v2link_client/core/logging_setup.py
- `test_sensitive_text_sanitizer_accepts_none_and_unusual_unicode()` --calls--> `sanitize_sensitive_text()`  [EXTRACTED]
  tests/test_logging_setup.py → src/v2link_client/core/logging_setup.py
- `test_sensitive_text_sanitizer_handles_malformed_url_port()` --calls--> `sanitize_sensitive_text()`  [EXTRACTED]
  tests/test_logging_setup.py → src/v2link_client/core/logging_setup.py
- `test_sensitive_text_sanitizer_preserves_xray_error_reason_and_field_name()` --calls--> `sanitize_sensitive_text()`  [EXTRACTED]
  tests/test_logging_setup.py → src/v2link_client/core/logging_setup.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Bounded Runtime Monitoring** — docs_development_runtime_invariants, docs_traffic_monitor_traffic_monitor, docs_runtime_performance_troubleshooting_runtime_diagnostics, docs_releases_v0_2_1_v0_2_1 [INFERRED 0.95]
- **Guarded Release Publication** — _github_workflows_release_release, docs_maintainer_release_maintainer_release_process, changelog_project_history, docs_releases_v0_2_4_v0_2_4 [INFERRED 0.95]
- **Proxy Operation Dashboard** — images_app_dark_connection_controls, images_app_dark_connectivity_monitoring, images_app_dark_runtime_metrics, images_app_dark_diagnostics_report [INFERRED 0.85]
- **Connection Observability Workflow** — images_app_light_proxy_configuration_controls, images_app_light_connection_status_monitoring, images_app_light_network_diagnostics_report, images_app_light_connectivity_failure_alert [INFERRED 0.85]
- **Traffic Analytics Views** — images_readme_dark_v0_2_1_usage_overview, images_readme_dark_v0_2_1_session_history, images_readme_dark_v0_2_1_session_speed_chart, images_readme_dark_v0_2_1_csv_export [INFERRED 0.95]
- **Proxy Operation Workflow** — images_readme_dark_v0_2_1_proxy_profile_control, images_readme_dark_v0_2_1_proxy_runtime_status, images_readme_dark_v0_2_1_connectivity_monitoring, images_readme_dark_v0_2_1_traffic_monitor [INFERRED 0.85]
- **Traffic Analysis Workspace** — images_readme_light_v0_2_1_traffic_monitor_overview, images_readme_light_v0_2_1_session_analytics, images_readme_light_v0_2_1_usage_charts, images_readme_light_v0_2_1_data_export [INFERRED 0.95]

## Communities (80 total, 19 thin omitted)

### Community 0 - "System Proxy Management"
Cohesion: 0.07
Nodes (81): CompletedProcess, fixture, ProxyBackendName, ProxyApplyError, _apply_runtime_proxy(), _capture_snapshot(), _decode_value(), _detect_backend() (+73 more)

### Community 1 - "Profile Storage and Editing"
Cohesion: 0.07
Nodes (31): QDialog, basic_url_prefix_valid(), detect_protocol(), _now_iso(), Profile, ProfileStore, Any, Path (+23 more)

### Community 2 - "Netmon Rust Service"
Cohesion: 0.05
Nodes (57): AppCounters, AppIdentity, DiagnosticsResponse, HistoryResponse, LiveResponse, Option, String, Vec (+49 more)

### Community 3 - "Diagnostics UI and Sanitization"
Cohesion: 0.06
Nodes (42): QApplication, Sanitizer, DiagnosticsWidget, DiagnosticsWorker, DiagnosticsWorkerSignals, Any, QObject, QRunnable (+34 more)

### Community 4 - "Netmon Client Integration"
Cohesion: 0.09
Nodes (42): _app_from_payload(), _backend_message(), _backend_remediation(), _backend_state(), _bool_field(), _InstallationEvidence, _int_value(), NetmonClient (+34 more)

### Community 5 - "Versioning and Health Checks"
Cohesion: 0.05
Nodes (30): check_http_proxy(), _prefer_failure(), ProxyHealthResult, Connectivity checks for the running core. We treat the core as "online" when an…, _try_urls(), v2link-client package., get_project_version(), get_semver() (+22 more)

### Community 6 - "Link Parsing and Configuration"
Cohesion: 0.08
Nodes (47): build_xray_config(), _build_xray_stream_settings(), Any, ParsedLink, Path, Build core configuration files. At the moment, the app targets Xray-core…, InvalidLinkError, _first() (+39 more)

### Community 7 - "Diagnostics Subprocess Environment"
Cohesion: 0.09
Nodes (43): _append_recent_error(), _append_runtime_state(), _append_traffic_storage(), build_diagnostics_report(), collect_diagnostics(), _collect_diagnostics_text(), CommandReport, _db_app_tables_present() (+35 more)

### Community 8 - "Traffic Monitor Refresh UI"
Cohesion: 0.08
Nodes (8): format_bytes(), format_mbps(), _elide_middle(), Invalidate UI jobs without stopping the independent netmon service., Update only the live labels; this method never reads from storage., Refresh only the active section, and never refresh a hidden monitor…, Explicit full refresh retained for settings changes and compatibility., TrafficMonitorWidget

### Community 10 - "Traffic Hot Path Testing"
Cohesion: 0.09
Nodes (33): RuntimeError, get_traffic_settings_path(), load_traffic_settings(), _positive_int(), Any, Path, Traffic Monitor settings persistence., _retention_value() (+25 more)

### Community 11 - "Xray Discovery and Settings"
Cohesion: 0.11
Nodes (39): load_json(), Any, _candidate_from_env_dir(), _dedupe(), _executable_dir(), find_xray_binary(), get_bundled_xray_candidates(), get_system_xray_candidate() (+31 more)

### Community 12 - "Traffic Monitor Components"
Cohesion: 0.19
Nodes (21): QTableWidgetItem, AppIdentity, DailyUsageBreakdown, ProxySessionDetail, ProxySessionSummary, ProxyTrafficSample, Persistent proxy and application traffic history backed by SQLite., TrafficUsageSummary (+13 more)

### Community 13 - "Traffic Database Operations"
Cohesion: 0.13
Nodes (10): Row, AppTrafficSample, _clean_confidence(), _clean_source(), _next_month_start(), _now(), _parse_iso(), datetime (+2 more)

### Community 14 - "Chart Theme Rendering"
Cohesion: 0.16
Nodes (14): QColor, QPainter, QRectF, apply_theme(), _dark_theme(), get_theme(), _light_theme(), normalize_theme() (+6 more)

### Community 15 - "Traffic Store Queries"
Cohesion: 0.18
Nodes (20): Return peak-preserving time buckets without returning an unbounded row set., TrafficStore, _stats(), test_active_and_crashed_session_status(), test_app_usage_aggregation(), test_clear_history_requires_explicit_call(), test_counter_reset_handling(), test_csv_export() (+12 more)

### Community 16 - "Runtime Error State"
Cohesion: 0.18
Nodes (6): LogRecord, Remove common credentials before text reaches logs, UI, or exports. This is the…, sanitize_sensitive_text(), cancel_active_stats_queries(), Terminate and reap only stats-query children started by this process., Perform the ordered, idempotent application-owned shutdown.

### Community 17 - "Validation Error UI Tests"
Cohesion: 0.20
Nodes (15): test_dialog_validation_failure_is_sanitized_before_latest_error_storage(), test_disabled_tracking_does_not_poll_or_retain_helper_errors(), test_expected_missing_socket_clears_an_earlier_netmon_error(), test_latest_error_provider_returns_none_until_an_active_error_exists(), test_normal_optional_netmon_states_do_not_become_errors(), test_profile_parse_failure_uses_profile_import_category(), test_structured_netmon_failure_becomes_sanitized_error_then_clears(), test_successful_validation_clears_only_validation_categories() (+7 more)

### Community 18 - "Humanized Session Timestamps"
Cohesion: 0.18
Nodes (9): format_date(), format_datetime(), format_duration(), format_duration_s(), format_speed(), format_time_only(), _parse_datetime(), datetime (+1 more)

### Community 19 - "Traffic Storage Worker"
Cohesion: 0.16
Nodes (4): Serialize SQLite writes away from Qt with a bounded, drainable queue., _StorageCommand, TrafficStorageWorker, RetentionCleanupResult

### Community 20 - "Update Checking"
Cohesion: 0.19
Nodes (18): check_for_updates(), is_update_available(), normalize_version(), parse_release_payload(), parse_version(), _pick_assets(), Any, Check GitHub releases for newer versions. (+10 more)

### Community 21 - "Latest Error Formatting"
Cohesion: 0.17
Nodes (15): format_latest_error(), LatestError, _normalize_timestamp(), datetime, Small, privacy-preserving store for user-relevant application errors., Sanitize and retain an active error; informational events are ignored., A sanitized error safe to retain in UI runtime state., Format one latest-error record for the same safe export pipeline. (+7 more)

### Community 22 - "Latest Error Store Tests"
Cohesion: 0.18
Nodes (14): LatestErrorStore, Track the newest active error per source without retaining raw details., Clear only the named operation/source after its successful recovery., test_clear_all_removes_every_active_error(), test_compound_and_camel_case_secret_context_keys_are_redacted(), test_error_is_sanitized_before_storage_and_formatting(), test_informational_warning_is_not_stored_as_latest_error(), test_latest_active_uses_timestamp_and_source_specific_clear() (+6 more)

### Community 23 - "Linux Process Sampling"
Cohesion: 0.27
Nodes (16): PidCounter, app_id(), is_xray(), ProcessInfo, read_cgroup(), read_comm(), read_process(), read_uid() (+8 more)

### Community 24 - "Link Validation and Profiles"
Cohesion: 0.18
Nodes (5): BaseException, connection_fingerprint(), Stable hash for connection-defining URL content., save_json(), Path

### Community 25 - "Xray API Errors"
Cohesion: 0.24
Nodes (14): Exception, AppError, BinaryMissingError, PermissionDeniedError, PortInUseError, Typed application errors with user-facing messages., Base application error., ensure_port_available() (+6 more)

### Community 26 - "Secure Logging Pipeline"
Cohesion: 0.14
Nodes (14): Formatter, Handler, Match, Logging configuration and redaction helpers., Ensure ordinary log records cannot carry raw secret-bearing arguments., Backward-compatible alias for the shared sensitive-text sanitizer., Sanitize the final line, including any formatted exception traceback., redact() (+6 more)

### Community 27 - "Traffic Stats Lifecycle"
Cohesion: 0.18
Nodes (9): HourlyUsage, ProfileTrafficSummary, Any, _stats_pair(), TrafficHistoryDiagnostics, TrafficStats, _ShutdownHarness, test_late_health_result_is_ignored_while_closing() (+1 more)

### Community 28 - "Xray Process Management"
Cohesion: 0.21
Nodes (13): Popen, _append_bounded(), _bound_existing_log(), _bound_pending_output(), find_free_port(), _pump_bounded_stdout(), Path, Manage core process lifecycle. The UI intentionally keeps policy decisions… (+5 more)

### Community 30 - "Session Chart Data"
Cohesion: 0.24
Nodes (13): downsample_session_chart_points(), prepare_session_cumulative_chart_data(), prepare_session_speed_chart_data(), Min/max bucket a paired series while preserving endpoints and chronological…, SessionChartPoint, _app(), parametrize, _sample() (+5 more)

### Community 31 - "Project Architecture Documentation"
Cohesion: 0.16
Nodes (15): CI Workflow, Guarded Release Workflow, v2link-client Project History, Bounded Runtime Invariants, Maintainer Release Process, v2link-client v0.2.0, v2link-client v0.2.1, v2link-client v0.2.4 (+7 more)

### Community 32 - "Traffic UI Layout"
Cohesion: 0.37
Nodes (5): QGridLayout, QLabel, QScrollArea, QWidget, _wrap_scroll_area()

### Community 33 - "Process Manager Tests"
Cohesion: 0.22
Nodes (13): ConfigBuildError, validate_xray_config(), _process_gone(), parametrize, Path, _script(), _SyntheticProcess, test_validate_xray_config_sanitizes_subprocess_error() (+5 more)

### Community 34 - "Network Health Workers"
Cohesion: 0.23
Nodes (11): UnsupportedSchemeError, ping_server(), Network probes (ping-like checks) for remote servers., ServerPingResult, SystemProxyAuditResult, Simple speed test through the local HTTP proxy inbound. This is not meant to…, run_speed_test_via_http_proxy(), SpeedTestResult (+3 more)

### Community 35 - "Traffic History Queries"
Cohesion: 0.16
Nodes (4): DailyTrafficUsage, get_traffic_db_path(), Path, _timestamp_range()

### Community 37 - "Storage Performance Tests"
Cohesion: 0.40
Nodes (12): _bulk_samples(), _session(), _stats(), test_automatic_chart_query_is_bounded_and_keeps_endpoints(), test_complete_sample_export_remains_unbounded(), test_existing_v2_database_migrates_without_losing_data(), test_retention_runs_at_most_daily_and_preserves_summaries(), test_storage_worker_batches_cumulative_counters_and_finalizes() (+4 more)

### Community 38 - "Application Entry and Assets"
Cohesion: 0.23
Nodes (9): get_app_icon_path(), Path, Resolve runtime asset locations for source and packaged builds., Path, setup_logging(), main(), Application entry point., test_get_app_icon_path_prefers_meipass_when_frozen() (+1 more)

### Community 42 - "TLS Probe Tests"
Cohesion: 0.25
Nodes (4): _FakeSocket, _FakeTlsContext, _FakeTlsSocket, test_tls_probe_always_retains_secure_certificate_verification()

### Community 43 - "Traffic UI Integration Tests"
Cohesion: 0.35
Nodes (9): _app(), _stats(), test_history_tab_builds_in_compact_and_workspace_modes(), test_history_tab_missing_data_does_not_crash(), test_history_tab_selecting_date_and_session_updates_details(), test_layout_state_save_restore_does_not_crash(), test_long_profile_names_do_not_crash_table_rendering(), test_main_window_geometry_save_restore_does_not_crash() (+1 more)

### Community 44 - "Traffic Monitor Dark UI"
Cohesion: 0.29
Nodes (10): Connectivity Monitoring, Traffic CSV Export, Dark Theme, Proxy Profile Control, Proxy Runtime Status, Session History, Selected Session Speed Chart, Traffic Monitor (+2 more)

### Community 45 - "Xray Fetch Script"
Cohesion: 0.33
Nodes (8): asset_for_arch(), copy_required_file(), manifest_value(), require_tool(), fetch_xray_core.sh script, sha_for_arch(), verify_directory(), verify_sha_is_set()

### Community 46 - "Owned Process Termination"
Cohesion: 0.31
Nodes (7): Signals, _owned_group_exists(), Any, Helpers for terminating process groups created by this application., Reap an app-owned process, escalating only its private process group., _signal_owned_group(), terminate_owned_process()

### Community 47 - "Xray Binary Runtime"
Cohesion: 0.33
Nodes (3): CoreBinary, find_xray_binary(), XrayProcessManager

### Community 48 - "Sanitized Logging Tests"
Cohesion: 0.28
Nodes (8): parametrize, test_large_nonmatching_unicode_input_has_bounded_runtime(), test_sensitive_text_sanitizer_accepts_none_and_unusual_unicode(), test_sensitive_text_sanitizer_covers_export_secret_categories(), test_sensitive_text_sanitizer_handles_malformed_url_port(), test_sensitive_text_sanitizer_preserves_useful_diagnostics(), test_sensitive_text_sanitizer_preserves_xray_error_reason_and_field_name(), test_sensitive_text_sanitizer_removes_synthetic_secrets()

### Community 49 - "Application Storage Paths"
Cohesion: 0.54
Nodes (7): ensure_dirs(), get_config_dir(), get_data_dir(), get_logs_dir(), get_state_dir(), Path, Storage paths and JSON helpers.

### Community 50 - "Desktop Dark Theme"
Cohesion: 0.43
Nodes (7): Connection Controls, Connectivity Monitoring, Dark Theme, System Diagnostics Report, Proxy Configuration, Runtime Metrics, v2link-client Desktop Interface (Dark Theme)

### Community 51 - "Traffic Monitor Light UI"
Cohesion: 0.43
Nodes (7): Connection Status and Connectivity, Traffic Data CSV Export, Proxy Connection Controls, Session Analytics, Traffic Monitor Overview, Download and Upload Usage Charts, v2link-client v0.2.1 Light Theme Screenshot

### Community 53 - "Xray API Process Tests"
Cohesion: 0.52
Nodes (6): active_stats_query_pid(), Path, _script(), test_cancel_active_stats_query_reaps_it(), test_statsquery_parses_json_and_reaps_child(), test_statsquery_timeout_is_bounded()

### Community 54 - "V2 Brand Logo"
Cohesion: 0.47
Nodes (6): Neon Blue and Magenta Palette, Orbital Swoosh Motif, Sparkle Accents, V2 App Logo, V2 App Wordmark, V2 Monogram

### Community 55 - "Desktop Light Theme"
Cohesion: 0.53
Nodes (6): Connection Status Monitoring, HTTPS Connectivity Failure Alert, Light Theme, Network Diagnostics Report, Proxy Configuration Controls, v2link-client Application Window

### Community 57 - "Development Runner"
Cohesion: 0.40
Nodes (3): PYTHONPATH, dev_run.sh script, V2LINK_BUNDLED_XRAY_DIR

### Community 59 - "Release Artifact Verification"
Cohesion: 0.90
Nodes (4): fail(), require_file(), require_mode(), verify_release_artifacts.sh script

### Community 60 - "Bundled Xray Licensing"
Cohesion: 0.50
Nodes (4): Bundled Xray-core, v2link-client v0.2.2, Xray-core Third-Party Notice, Project X / Xray-core

### Community 62 - "CI Workflow Tests"
Cohesion: 0.83
Nodes (3): test_ci_jobs_cover_required_validation_and_no_publication(), test_ci_workflow_exists_and_has_safe_triggers(), _workflow()

### Community 64 - "Packaged App Icon"
Cohesion: 0.67
Nodes (3): Connectivity and Motion Motif, V2 App Icon, V2 App Brand Identity

## Knowledge Gaps
- **25 isolated node(s):** `v2link-client`, `build_netmon.sh script`, `build_pyinstaller.sh script`, `build_release.sh script`, `VERSION` (+20 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **19 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MainWindow` connect `Main Window Orchestration` to `System Proxy Management`, `Profile Storage and Editing`, `Diagnostics UI and Sanitization`, `Netmon Client Integration`, `Versioning and Health Checks`, `Link Parsing and Configuration`, `Traffic Monitor Refresh UI`, `Traffic Hot Path Testing`, `Xray Discovery and Settings`, `Traffic Monitor Components`, `Traffic Store Queries`, `Runtime Error State`, `Validation Error UI Tests`, `Traffic Storage Worker`, `Update Checking`, `Latest Error Store Tests`, `Link Validation and Profiles`, `Xray API Errors`, `Traffic Stats Lifecycle`, `Runtime Diagnostics Polling`, `Network Health Workers`, `Application Entry and Assets`, `User Preferences and Theme`, `Health and Proxy Audits`, `Xray Binary Runtime`?**
  _High betweenness centrality (0.127) - this node is a cross-community bridge._
- **Why does `TrafficStore` connect `Traffic Store Queries` to `Traffic UI Layout`, `Network Health Workers`, `Traffic History Queries`, `Storage Performance Tests`, `User Preferences and Theme`, `Traffic Database Migrations`, `Health and Proxy Audits`, `Main Window Orchestration`, `Traffic Monitor Refresh UI`, `Traffic Monitor Components`, `Traffic Database Operations`, `Traffic Hot Path Testing`, `Traffic UI Integration Tests`, `Traffic Storage Worker`, `Secure Logging Pipeline`, `Traffic Stats Lifecycle`?**
  _High betweenness centrality (0.112) - this node is a cross-community bridge._
- **Why does `TrafficMonitorWidget` connect `Traffic Monitor Refresh UI` to `Traffic UI Layout`, `Network Health Workers`, `Diagnostics UI and Sanitization`, `Netmon Client Integration`, `Responsive Workspace Layout`, `User Preferences and Theme`, `Health and Proxy Audits`, `Main Window Orchestration`, `Traffic Hot Path Testing`, `Traffic Monitor Components`, `Traffic UI Integration Tests`, `Traffic Store Queries`, `Humanized Session Timestamps`, `Latest Error Store Tests`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Are the 30 inferred relationships involving `MainWindow` (e.g. with `AppError` and `InvalidLinkError`) actually correct?**
  _`MainWindow` has 30 INFERRED edges - model-reasoned connections that need verification._
- **Are the 26 inferred relationships involving `TrafficStore` (e.g. with `_StorageCommand` and `TrafficStorageWorker`) actually correct?**
  _`TrafficStore` has 26 INFERRED edges - model-reasoned connections that need verification._
- **Are the 31 inferred relationships involving `TrafficMonitorWidget` (e.g. with `HealthCheckWorker` and `HealthCheckWorkerSignals`) actually correct?**
  _`TrafficMonitorWidget` has 31 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `sanitize_sensitive_text()` (e.g. with `_redact_quoted_assignment()` and `_redact_url()`) actually correct?**
  _`sanitize_sensitive_text()` has 2 INFERRED edges - model-reasoned connections that need verification._