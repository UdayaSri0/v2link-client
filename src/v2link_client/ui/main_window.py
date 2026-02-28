"""Main application window."""

from __future__ import annotations

import logging
from pathlib import Path
import tempfile
import time

from PyQt6.QtCore import QObject, QRunnable, Qt, QThreadPool, QTimer, pyqtSignal
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from v2link_client import __author__, __version__
from v2link_client.core.config_builder import (
    DEFAULT_API_PORT,
    DEFAULT_HTTP_PORT,
    DEFAULT_LISTEN,
    DEFAULT_SOCKS_PORT,
    build_xray_config,
)
from v2link_client.core.errors import AppError
from v2link_client.core.health_check import ProxyHealthResult, check_http_proxy
from v2link_client.core.humanize import format_bytes, format_duration_s, format_mbps
from v2link_client.core.link_parser import parse_link
from v2link_client.core.net_probe import ServerPingResult, ping_server
from v2link_client.core.profile_store import Profile, ProfileStore
from v2link_client.core.proxy_manager import SystemProxyConfig, SystemProxyManager
from v2link_client.core.process_manager import (
    XrayProcessManager,
    ensure_port_available,
    find_free_port,
    find_xray_binary,
    validate_xray_config,
)
from v2link_client.core.speed_test import SpeedTestResult, run_speed_test_via_http_proxy
from v2link_client.core.storage import get_config_dir, get_state_dir, load_json, save_json
from v2link_client.core.xray_api import TrafficStats, get_outbound_traffic
from v2link_client.ui.diagnostics_widget import DiagnosticsWidget
from v2link_client.ui.profile_dialogs import ProfileEditorDialog, ProfileManagerDialog
from v2link_client.ui.theme import ThemeName, apply_theme, normalize_theme, theme_display_name

logger = logging.getLogger(__name__)

PROFILE_FILE = "profile.json"
XRAY_CONFIG_FILE = "xray_config.json"
PROFILE_KEY_APPLY_SYSTEM_PROXY = "apply_system_proxy"
PROFILE_KEY_APPLY_SYSTEM_PROXY_EXPLICIT = "apply_system_proxy_explicit"
PROFILE_KEY_PROFILES_MIGRATED = "profiles_migrated_v1"

HEALTH_INTERVAL_MS = 5000


class HealthCheckWorkerSignals(QObject):
    result = pyqtSignal(object)
    error = pyqtSignal(str)


class HealthCheckWorker(QRunnable):
    def __init__(self, fn) -> None:
        super().__init__()
        self.fn = fn
        self.signals = HealthCheckWorkerSignals()

    def run(self) -> None:
        try:
            payload = self.fn()
        except Exception as exc:  # pragma: no cover - defensive
            self.signals.error.emit(str(exc))
            return
        self.signals.result.emit(payload)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("v2link-client")
        self.resize(900, 640)

        self._setup_menu()

        self._theme: ThemeName = "dark"

        central = QWidget(self)
        central.setObjectName("central")
        self.setCentralWidget(central)

        self.link_input = QLineEdit()
        self.link_input.setPlaceholderText("Paste a vless:// link")

        self.profile_selector = QComboBox()
        self.profile_selector.setMinimumWidth(260)
        self.profile_selector.setToolTip("Select a saved profile")

        self.manage_profiles_button = QPushButton("Manage")
        self.manage_profiles_button.clicked.connect(self._on_manage_profiles_clicked)
        self.manage_profiles_button.setProperty("variant", "ghost")

        self.validate_button = QPushButton("Validate & Save")
        self.validate_button.clicked.connect(self._on_validate_clicked)
        self.validate_button.setProperty("variant", "primary")

        self.system_proxy_checkbox = QCheckBox("System Proxy")
        self.system_proxy_checkbox.setToolTip(
            "Apply system proxy settings while running so most apps use the tunnel automatically."
        )
        self.system_proxy_checkbox.setChecked(True)

        self.start_stop_button = QPushButton("Start")
        self.start_stop_button.setEnabled(False)
        self.start_stop_button.clicked.connect(self._on_start_stop_clicked)
        self.start_stop_button.setProperty("variant", "primary")

        self.ping_button = QPushButton("Ping Server")
        self.ping_button.setEnabled(False)
        self.ping_button.clicked.connect(self._on_ping_clicked)
        self.ping_button.setProperty("variant", "ghost")

        self.speed_test_button = QPushButton("Speed Test")
        self.speed_test_button.setEnabled(False)
        self.speed_test_button.clicked.connect(self._on_speed_test_clicked)
        self.speed_test_button.setProperty("variant", "ghost")

        self.status_label = QLabel("STOPPED")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.status_label.setProperty("role", "pill")

        self.health_label = QLabel("OFFLINE")
        self.health_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.health_label.setProperty("role", "pill")
        self._set_health_state("offline", "Not running")

        self.theme_selector = QComboBox()
        self.theme_selector.addItems(["Dark", "Light"])
        self.theme_selector.setFixedWidth(120)
        self.theme_selector.setToolTip("Switch theme")

        profile_row = QHBoxLayout()
        profile_row.setSpacing(10)
        profile_row.addWidget(QLabel("Profile"))
        profile_row.addWidget(self.profile_selector, 1)
        profile_row.addWidget(self.manage_profiles_button)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)
        top_row.addWidget(self.link_input, 1)
        top_row.addWidget(self.validate_button)
        top_row.addWidget(self.system_proxy_checkbox)
        top_row.addWidget(self.theme_selector)

        control_row = QHBoxLayout()
        control_row.setSpacing(10)
        control_row.addWidget(self.start_stop_button)
        control_row.addWidget(self.ping_button)
        control_row.addWidget(self.speed_test_button)
        control_row.addWidget(QLabel("Status:"))
        control_row.addWidget(self.status_label, 1)
        control_row.addWidget(QLabel("Connectivity:"))
        control_row.addWidget(self.health_label)

        self.uptime_label = QLabel("UPTIME (00:00:00)")
        self.uptime_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.uptime_label.setProperty("role", "pill")

        self.speed_label = QLabel("SPEED (↑ 0.0 Mbps / ↓ 0.0 Mbps)")
        self.speed_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.speed_label.setProperty("role", "pill")

        self.traffic_label = QLabel("TRAFFIC (↑ 0 B / ↓ 0 B)")
        self.traffic_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.traffic_label.setProperty("role", "pill")

        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(10)
        metrics_row.addWidget(self.uptime_label)
        metrics_row.addWidget(self.speed_label, 1)
        metrics_row.addWidget(self.traffic_label)

        self.diagnostics_widget = DiagnosticsWidget()

        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        layout.addLayout(profile_row)
        layout.addLayout(top_row)
        layout.addLayout(control_row)
        layout.addLayout(metrics_row)
        layout.addWidget(self.diagnostics_widget, 1)

        central.setLayout(layout)

        self._process = XrayProcessManager()
        self._validated_config_path = None
        self._validated_link = None
        self._socks_port = DEFAULT_SOCKS_PORT
        self._http_port = DEFAULT_HTTP_PORT
        self._api_port: int | None = None
        self.diagnostics_widget.set_proxy_ports(
            socks_port=self._socks_port, http_port=self._http_port
        )
        self._thread_pool = QThreadPool.globalInstance()
        self._profile_store = ProfileStore()
        self._selected_profile_id: str | None = None
        self._profile_selector_syncing = False

        self._system_proxy = SystemProxyManager()
        self._system_proxy_applied = False
        if not self._system_proxy.is_supported():
            self.system_proxy_checkbox.setEnabled(False)
            self.system_proxy_checkbox.setToolTip(
                "System proxy auto-apply is not supported on this desktop yet. Use manual proxy settings."
            )

        self._health_timer = QTimer(self)
        self._health_timer.setInterval(HEALTH_INTERVAL_MS)
        self._health_timer.timeout.connect(self._kick_health_check)
        self._health_in_flight = False
        self._health_token = 0
        self._last_health_ok: bool | None = None

        self._status_timer = QTimer(self)
        self._status_timer.setInterval(1000)
        self._status_timer.timeout.connect(self._poll_core_status)

        self._core_started_at: float | None = None
        self._stats_in_flight = False
        self._stats_token = 0
        self._last_stats_at: float | None = None
        self._last_uplink: int | None = None
        self._last_downlink: int | None = None
        self._ping_in_flight = False
        self._speed_test_in_flight = False

        profile_data = self._load_profile()
        self._load_saved_profiles(profile_data)
        self.profile_selector.currentIndexChanged.connect(self._on_profile_selected)
        self.system_proxy_checkbox.toggled.connect(self._on_system_proxy_toggled)
        self._apply_theme(self._theme, persist=False)
        self.theme_selector.currentTextChanged.connect(self._on_theme_changed)

        # If the app previously applied system proxy and crashed, attempt to restore.
        try:
            if self._system_proxy.restore_if_needed():
                logger.info("Restored system proxy from previous session")
        except Exception:
            logger.exception("Failed to restore system proxy from previous session")
        try:
            if self._system_proxy.repair_stale_loopback_proxy():
                logger.info("Repaired stale loopback proxy settings from previous session")
                self.diagnostics_widget.set_hint(
                    "Detected stale system proxy settings and reset to no-proxy."
                )
        except Exception:
            logger.exception("Failed to auto-repair stale loopback proxy settings")

    def _setup_menu(self) -> None:
        help_menu = self.menuBar().addMenu("&Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _show_about(self) -> None:
        text = (
            "<b>v2link-client</b><br>"
            f"Version: {__version__}<br>"
            f"Author: {__author__}<br><br>"
            "Linux desktop client for V2Ray-style links (VLESS) built with Python + PyQt6.<br>"
            "Powered by Xray-core.<br><br>"
            "<b>What's New</b><br>"
            "• Save multiple VPN URLs as profiles<br>"
            "• Quickly switch profiles from dropdown<br>"
            "• Manage profiles (edit/delete/default)<br>"
            "• Safer config saving with atomic writes"
        )
        QMessageBox.about(self, "About v2link-client", text)

    def _on_validate_clicked(self) -> None:
        self._reset_validation_state()
        raw_link = self.link_input.text().strip()

        try:
            parsed_link, config_path, xray, socks_port, http_port, api_port = self._validate_link(
                raw_link, persist_runtime_config=True
            )
        except AppError as exc:
            self.diagnostics_widget.set_hint(exc.user_message)
            return
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Validation failed")
            self.diagnostics_widget.set_hint(f"Validation failed: {exc}")
            return

        saved_profile = self._handle_profile_save_after_validation(raw_link, parsed_link)
        if saved_profile is not None:
            self._selected_profile_id = saved_profile.id
            self._refresh_profile_selector(select_profile_id=saved_profile.id)
        else:
            existing = self._profile_store.find_by_url(raw_link)
            if existing is not None:
                self._selected_profile_id = existing.id
                self._refresh_profile_selector(select_profile_id=existing.id)

        self._save_profile_preferences(link=raw_link)
        self._process = XrayProcessManager(xray)
        self._validated_config_path = config_path
        self._validated_link = parsed_link
        self._socks_port = socks_port
        self._http_port = http_port
        self._api_port = api_port
        self.diagnostics_widget.set_proxy_ports(
            socks_port=self._socks_port, http_port=self._http_port
        )
        self.start_stop_button.setEnabled(True)
        self.ping_button.setEnabled(True)

        hint = (
            f"Validated: {parsed_link.display_name()}. "
            f"Ready to start (SOCKS5 {DEFAULT_LISTEN}:{self._socks_port}, HTTP {DEFAULT_LISTEN}:{self._http_port})."
        )
        warning = self._validation_warning(parsed_link)
        if warning:
            hint = f"{hint}  Warning: {warning}"
        if saved_profile is not None:
            hint = f"{hint} Profile saved: {saved_profile.name}."
        elif self._profile_store.find_by_url(raw_link) is not None:
            hint = f"{hint} Using existing saved profile."
        else:
            hint = f"{hint} URL validated but not saved as a profile."
        self.diagnostics_widget.set_hint(hint)
        self._set_health_state("offline", "Not running")

    def _reset_validation_state(self) -> None:
        self.status_label.setText("STOPPED")
        self._validated_config_path = None
        self._validated_link = None
        self.start_stop_button.setEnabled(False)
        self.ping_button.setEnabled(False)
        self.speed_test_button.setEnabled(False)
        self.system_proxy_checkbox.setEnabled(self._system_proxy.is_supported())
        self._api_port = None
        self._core_started_at = None
        self._stats_token += 1
        self._last_stats_at = None
        self._last_uplink = None
        self._last_downlink = None
        self._set_metrics_defaults()

    def _validate_link(
        self, raw_link: str, *, persist_runtime_config: bool
    ) -> tuple[object, Path, object, int, int, int]:
        parsed_link = parse_link(raw_link)
        socks_port, http_port, api_port = self._pick_proxy_ports()
        config = build_xray_config(
            parsed_link, socks_port=socks_port, http_port=http_port, api_port=api_port
        )

        if persist_runtime_config:
            config_path = get_state_dir() / XRAY_CONFIG_FILE
            save_json(config_path, config)
        else:
            with tempfile.NamedTemporaryFile(
                prefix="xray_validate_",
                suffix=".json",
                dir=str(get_state_dir()),
                delete=False,
            ) as handle:
                config_path = Path(handle.name)
            save_json(config_path, config)

        xray = find_xray_binary()
        try:
            validate_xray_config(xray, config_path)
        except Exception:
            if not persist_runtime_config:
                try:
                    config_path.unlink(missing_ok=True)
                except Exception:
                    logger.exception("Failed to clean temporary validation config")
            raise

        if not persist_runtime_config:
            try:
                config_path.unlink(missing_ok=True)
            except Exception:
                logger.exception("Failed to clean temporary validation config")

        return parsed_link, config_path, xray, socks_port, http_port, api_port

    def _validate_link_for_dialog(self, raw_link: str) -> tuple[bool, str]:
        try:
            parsed_link, _, _, _, _, _ = self._validate_link(raw_link, persist_runtime_config=False)
        except AppError as exc:
            return False, exc.user_message
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Validation failed in profile dialog")
            return False, f"Validation failed: {exc}"
        return True, f"Valid: {parsed_link.display_name()}"

    def _handle_profile_save_after_validation(self, raw_link: str, parsed_link) -> Profile | None:
        existing = self._profile_store.find_by_url(raw_link)
        if existing is not None:
            chooser = QMessageBox(self)
            chooser.setIcon(QMessageBox.Icon.Question)
            chooser.setWindowTitle("URL Already Saved")
            chooser.setText(
                f"This URL is already saved in profile '{existing.name}'. "
                "Do you want to update it or save as a new profile?"
            )
            update_button = chooser.addButton("Update Profile", QMessageBox.ButtonRole.AcceptRole)
            save_new_button = chooser.addButton("Save as New", QMessageBox.ButtonRole.ActionRole)
            chooser.addButton("Keep Existing", QMessageBox.ButtonRole.RejectRole)
            chooser.setDefaultButton(update_button)
            chooser.exec()
            clicked = chooser.clickedButton()
            if clicked == update_button:
                return self._edit_profile(existing, forced_url=raw_link)
            if clicked == save_new_button:
                return self._add_profile(raw_link=raw_link, suggested_name=self._suggest_profile_name(parsed_link))
            return existing

        return self._add_profile(raw_link=raw_link, suggested_name=self._suggest_profile_name(parsed_link))

    def _suggest_profile_name(self, parsed_link) -> str:
        name = ""
        try:
            name = str(parsed_link.display_name())
        except Exception:  # pragma: no cover - defensive
            name = ""
        return name.strip() or "Saved Profile"

    def _add_profile(self, *, raw_link: str, suggested_name: str) -> Profile | None:
        dialog = ProfileEditorDialog(
            validate_fn=self._validate_link_for_dialog,
            default_profile_id=self._profile_store.default_profile_id,
            preset_url=raw_link,
            parent=self,
        )
        dialog.name_input.setText(suggested_name)
        if self._profile_store.default_profile_id is None:
            dialog.default_checkbox.setChecked(True)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None

        profile = self._profile_store.add_profile(dialog.build_profile())
        if dialog.set_as_default:
            self._profile_store.set_default(profile.id)
        return profile

    def _edit_profile(self, profile: Profile, *, forced_url: str | None = None) -> Profile | None:
        dialog = ProfileEditorDialog(
            validate_fn=self._validate_link_for_dialog,
            profile=profile,
            default_profile_id=self._profile_store.default_profile_id,
            parent=self,
        )
        if forced_url:
            dialog.url_input.setText(forced_url)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None

        updated = self._profile_store.update_profile(dialog.build_profile())
        if dialog.set_as_default:
            self._profile_store.set_default(updated.id)
        return updated

    def _on_start_stop_clicked(self) -> None:
        if self._process.is_running():
            self._stop_core(user_message="Stopped.")
            return

        if not self._validated_config_path:
            self.diagnostics_widget.set_hint("Validate & Save a link first.")
            return

        try:
            ensure_port_available(DEFAULT_LISTEN, self._socks_port)
            ensure_port_available(DEFAULT_LISTEN, self._http_port)
            if self._api_port is not None:
                ensure_port_available(DEFAULT_LISTEN, int(self._api_port))
            self._process.start(self._validated_config_path)
        except AppError as exc:
            self.diagnostics_widget.set_hint(exc.user_message)
            return
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Start failed")
            self.diagnostics_widget.set_hint(f"Start failed: {exc}")
            return

        self.status_label.setText("RUNNING")
        self.start_stop_button.setText("Stop")
        self.start_stop_button.setProperty("variant", "danger")
        self._refresh_style(self.start_stop_button)
        self.link_input.setEnabled(False)
        self.profile_selector.setEnabled(False)
        self.manage_profiles_button.setEnabled(False)
        self.validate_button.setEnabled(False)
        self.system_proxy_checkbox.setEnabled(False)
        self.ping_button.setEnabled(False)
        self.speed_test_button.setEnabled(True)
        self._core_started_at = time.monotonic()
        self._stats_token += 1
        self._last_stats_at = None
        self._last_uplink = None
        self._last_downlink = None
        self._health_token += 1
        self._last_health_ok = None
        self._set_health_state("connecting", "Checking…")
        self._health_timer.start()
        self._kick_health_check()
        base_hint = (
            f"Started Xray. SOCKS5 {DEFAULT_LISTEN}:{self._socks_port} / "
            f"HTTP {DEFAULT_LISTEN}:{self._http_port}"
        )
        self.diagnostics_widget.set_hint(base_hint)
        self._mark_profile_last_used()
        if self.system_proxy_checkbox.isChecked():
            self._apply_system_proxy()
        else:
            self.diagnostics_widget.set_hint(
                f"{base_hint}. System Proxy is OFF, so only apps configured to use these local "
                "proxy ports will use the tunnel."
            )
        self._status_timer.start()

    def _poll_core_status(self) -> None:
        if self._process.is_running():
            self._update_uptime()
            self._kick_stats_poll()
            return

        code = self._process.returncode()
        self._status_timer.stop()
        self.status_label.setText("STOPPED")
        self.start_stop_button.setText("Start")
        self.start_stop_button.setProperty("variant", "primary")
        self._refresh_style(self.start_stop_button)
        self.link_input.setEnabled(True)
        self.profile_selector.setEnabled(True)
        self.manage_profiles_button.setEnabled(True)
        self.validate_button.setEnabled(True)
        self.system_proxy_checkbox.setEnabled(self._system_proxy.is_supported())
        self.ping_button.setEnabled(True if self._validated_link is not None else False)
        self.speed_test_button.setEnabled(False)
        self._health_timer.stop()
        self._health_token += 1
        self._stats_token += 1
        self._set_health_state("offline", "Not running")
        proxy_note = self._restore_system_proxy()
        self._core_started_at = None
        self._set_metrics_defaults()

        suffix = f" (exit code {code})" if code is not None else ""
        hint = f"Core stopped{suffix}. Check logs for details."
        if self._process.stdout_path:
            hint = f"Core stopped{suffix}. Logs: {self._process.stdout_path}"
        if proxy_note:
            hint = f"{hint} {proxy_note}"
        self.diagnostics_widget.set_hint(hint)

    def _stop_core(self, *, user_message: str) -> None:
        self._status_timer.stop()
        self._health_timer.stop()
        self._health_token += 1
        self._stats_token += 1
        try:
            self._process.stop()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Stop failed")

        self.status_label.setText("STOPPED")
        self.start_stop_button.setText("Start")
        self.start_stop_button.setProperty("variant", "primary")
        self._refresh_style(self.start_stop_button)
        self.link_input.setEnabled(True)
        self.profile_selector.setEnabled(True)
        self.manage_profiles_button.setEnabled(True)
        self.validate_button.setEnabled(True)
        self.system_proxy_checkbox.setEnabled(self._system_proxy.is_supported())
        self.ping_button.setEnabled(True if self._validated_link is not None else False)
        self.speed_test_button.setEnabled(False)
        self._set_health_state("offline", "Not running")
        proxy_note = self._restore_system_proxy()
        self._core_started_at = None
        self._set_metrics_defaults()
        if proxy_note:
            self.diagnostics_widget.set_hint(f"{user_message} {proxy_note}")
        else:
            self.diagnostics_widget.set_hint(user_message)

    def _load_profile(self) -> dict:
        profile_path = get_config_dir() / PROFILE_FILE
        data = load_json(profile_path, {})
        if not isinstance(data, dict):
            data = {}

        self._theme = normalize_theme(data.get("theme"))
        self.theme_selector.setCurrentText(theme_display_name(self._theme))
        supported = self._system_proxy.is_supported()
        apply_system_proxy = data.get(PROFILE_KEY_APPLY_SYSTEM_PROXY)
        apply_system_proxy_explicit = data.get(PROFILE_KEY_APPLY_SYSTEM_PROXY_EXPLICIT)

        changed = False
        resolved_apply_system_proxy = supported

        if isinstance(apply_system_proxy, bool) and isinstance(apply_system_proxy_explicit, bool):
            resolved_apply_system_proxy = apply_system_proxy and supported
        elif isinstance(apply_system_proxy, bool):
            # Legacy migration: older versions persisted unchecked as a silent default.
            resolved_apply_system_proxy = supported
            data[PROFILE_KEY_APPLY_SYSTEM_PROXY] = resolved_apply_system_proxy
            data[PROFILE_KEY_APPLY_SYSTEM_PROXY_EXPLICIT] = True
            changed = True
        else:
            data[PROFILE_KEY_APPLY_SYSTEM_PROXY] = resolved_apply_system_proxy
            data[PROFILE_KEY_APPLY_SYSTEM_PROXY_EXPLICIT] = True
            changed = True

        self.system_proxy_checkbox.setChecked(resolved_apply_system_proxy)
        if changed:
            save_json(profile_path, data)
        return data

    def _load_saved_profiles(self, profile_data: dict) -> None:
        self._profile_store.load()
        if self._profile_store.last_load_error:
            QMessageBox.warning(
                self,
                "Saved Profiles Error",
                self._profile_store.last_load_error,
            )
            self.diagnostics_widget.set_hint(self._profile_store.last_load_error)

        self._migrate_legacy_link(profile_data)
        self._refresh_profile_selector(select_profile_id=self._profile_store.default_profile_id)

        default_profile = self._profile_store.get_default()
        if default_profile is not None:
            self._set_selected_profile(default_profile.id, populate_url=True)
            return

        legacy_link = profile_data.get("link")
        if isinstance(legacy_link, str) and legacy_link.strip():
            self.link_input.setText(legacy_link.strip())
            existing = self._profile_store.find_by_url(legacy_link.strip())
            self._selected_profile_id = existing.id if existing is not None else None
            self._refresh_profile_selector(select_profile_id=self._selected_profile_id)

    def _migrate_legacy_link(self, profile_data: dict) -> None:
        already_migrated = bool(profile_data.get(PROFILE_KEY_PROFILES_MIGRATED))
        if already_migrated:
            return

        imported = False
        legacy_link = profile_data.get("link")
        if isinstance(legacy_link, str) and legacy_link.strip() and not self._profile_store.profiles:
            name = "Imported Profile"
            try:
                parsed_link = parse_link(legacy_link.strip())
                display_name = parsed_link.display_name().strip()
                if display_name:
                    name = display_name
            except AppError:
                pass
            profile = Profile.create(name=name, url=legacy_link.strip())
            saved_profile = self._profile_store.add_profile(profile)
            self._profile_store.set_default(saved_profile.id)
            imported = True

        profile_data[PROFILE_KEY_PROFILES_MIGRATED] = True
        save_json(get_config_dir() / PROFILE_FILE, profile_data)
        if imported:
            self.diagnostics_widget.set_hint("Imported your previous saved URL into Saved Profiles.")

    def _refresh_profile_selector(self, *, select_profile_id: str | None = None) -> None:
        profiles = sorted(
            self._profile_store.profiles,
            key=lambda profile: (not profile.favorite, profile.name.lower(), profile.created_at),
        )
        current_target = select_profile_id or self._selected_profile_id

        self._profile_selector_syncing = True
        self.profile_selector.blockSignals(True)
        self.profile_selector.clear()
        self.profile_selector.addItem("Select profile...", None)

        selected_index = 0
        for profile in profiles:
            label = profile.name
            if profile.favorite:
                label = f"★ {label}"
            if self._profile_store.default_profile_id == profile.id:
                label = f"{label} (default)"
            self.profile_selector.addItem(label, profile.id)
            if current_target and current_target == profile.id:
                selected_index = self.profile_selector.count() - 1

        self.profile_selector.setCurrentIndex(selected_index)
        self.profile_selector.blockSignals(False)
        self._profile_selector_syncing = False

    def _set_selected_profile(self, profile_id: str | None, *, populate_url: bool) -> None:
        self._selected_profile_id = profile_id
        self._refresh_profile_selector(select_profile_id=profile_id)
        if not populate_url or not profile_id:
            return
        profile = self._profile_store.get_by_id(profile_id)
        if profile is not None:
            self.link_input.setText(profile.url)

    def _on_profile_selected(self, index: int) -> None:
        if self._profile_selector_syncing:
            return
        profile_id = self.profile_selector.itemData(index)
        if not isinstance(profile_id, str):
            self._selected_profile_id = None
            return

        profile = self._profile_store.get_by_id(profile_id)
        if profile is None:
            self._selected_profile_id = None
            return

        self._selected_profile_id = profile.id
        self.link_input.setText(profile.url)

    def _on_manage_profiles_clicked(self) -> None:
        dialog = ProfileManagerDialog(
            store=self._profile_store,
            validate_fn=self._validate_link_for_dialog,
            parent=self,
        )
        dialog.exec()
        if not dialog.changed:
            return

        current_url = self.link_input.text().strip()
        matched_profile = self._profile_store.find_by_url(current_url)
        target_id = matched_profile.id if matched_profile is not None else self._profile_store.default_profile_id
        self._set_selected_profile(target_id, populate_url=False)

        if not current_url:
            default_profile = self._profile_store.get_default()
            if default_profile is not None:
                self._set_selected_profile(default_profile.id, populate_url=True)

    def _mark_profile_last_used(self) -> None:
        current_url = self.link_input.text().strip()
        if not current_url:
            return

        profile = None
        if self._selected_profile_id:
            selected = self._profile_store.get_by_id(self._selected_profile_id)
            if selected is not None and selected.url.strip() == current_url:
                profile = selected
        if profile is None:
            profile = self._profile_store.find_by_url(current_url)
        if profile is None:
            return

        self._profile_store.touch_last_used(profile.id)
        self._set_selected_profile(profile.id, populate_url=False)

    def _on_system_proxy_toggled(self, checked: bool) -> None:
        self._save_profile_preferences()

    def _on_theme_changed(self, value: str) -> None:
        self._apply_theme(normalize_theme(value), persist=True)

    def _apply_theme(self, theme: ThemeName, *, persist: bool) -> None:
        self._theme = theme
        app = QApplication.instance()
        if app is not None:
            apply_theme(app, theme)

        if persist:
            self._save_profile_preferences()

        self.theme_selector.blockSignals(True)
        self.theme_selector.setCurrentText(theme_display_name(theme))
        self.theme_selector.blockSignals(False)

        for widget in (
            self.validate_button,
            self.start_stop_button,
            self.theme_selector,
            self.manage_profiles_button,
            self.profile_selector,
        ):
            self._refresh_style(widget)

    def _save_profile_preferences(self, *, link: str | None = None) -> None:
        profile_path = get_config_dir() / PROFILE_FILE
        data = load_json(profile_path, {})
        if not isinstance(data, dict):
            data = {}
        data["theme"] = self._theme
        data[PROFILE_KEY_APPLY_SYSTEM_PROXY] = bool(self.system_proxy_checkbox.isChecked())
        data[PROFILE_KEY_APPLY_SYSTEM_PROXY_EXPLICIT] = True
        if link is not None:
            data["link"] = link
        save_json(profile_path, data)

    def _refresh_style(self, widget) -> None:
        style = widget.style()
        style.unpolish(widget)
        style.polish(widget)
        widget.update()

    def _pick_proxy_ports(self) -> tuple[int, int, int]:
        socks_port = DEFAULT_SOCKS_PORT
        http_port = DEFAULT_HTTP_PORT
        api_port = DEFAULT_API_PORT

        try:
            ensure_port_available(DEFAULT_LISTEN, socks_port)
        except AppError:
            socks_port = find_free_port(DEFAULT_LISTEN)

        try:
            ensure_port_available(DEFAULT_LISTEN, http_port)
        except AppError:
            http_port = find_free_port(DEFAULT_LISTEN)

        while http_port == socks_port:
            http_port = find_free_port(DEFAULT_LISTEN)

        try:
            ensure_port_available(DEFAULT_LISTEN, api_port)
        except AppError:
            api_port = find_free_port(DEFAULT_LISTEN)

        while api_port in {socks_port, http_port}:
            api_port = find_free_port(DEFAULT_LISTEN)

        return socks_port, http_port, api_port

    def _set_metrics_defaults(self) -> None:
        self.uptime_label.setText("UPTIME (00:00:00)")
        self.speed_label.setText("SPEED (↑ 0.0 Mbps / ↓ 0.0 Mbps)")
        self.traffic_label.setText("TRAFFIC (↑ 0 B / ↓ 0 B)")

    def _update_uptime(self) -> None:
        if self._core_started_at is None:
            self.uptime_label.setText("UPTIME (00:00:00)")
            return
        self.uptime_label.setText(
            f"UPTIME ({format_duration_s(time.monotonic() - self._core_started_at)})"
        )

    def _kick_stats_poll(self) -> None:
        if self._stats_in_flight:
            return
        if self._api_port is None:
            return
        if not self._process.is_running():
            return

        token = self._stats_token
        api_server = f"{DEFAULT_LISTEN}:{self._api_port}"
        xray_path = self._process.binary.path
        self._stats_in_flight = True

        def _run():
            stats = get_outbound_traffic(xray_path, server=api_server)
            return token, time.monotonic(), stats

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_stats_result)
        worker.signals.error.connect(lambda msg: self._on_stats_error(token, msg))
        self._thread_pool.start(worker)

    def _on_stats_result(self, payload: object) -> None:
        self._stats_in_flight = False
        token, now, stats = payload  # type: ignore[misc]
        if token != self._stats_token:
            return
        if not isinstance(stats, TrafficStats):  # pragma: no cover - defensive
            return

        self.traffic_label.setText(
            f"TRAFFIC (↑ {format_bytes(stats.uplink_bytes)} / ↓ {format_bytes(stats.downlink_bytes)})"
        )

        # Speed = delta bytes / delta time.
        if self._last_stats_at is not None and self._last_uplink is not None and self._last_downlink is not None:
            dt = max(0.001, float(now) - float(self._last_stats_at))
            up_bps = (stats.uplink_bytes - self._last_uplink) / dt
            down_bps = (stats.downlink_bytes - self._last_downlink) / dt
            self.speed_label.setText(
                f"SPEED (↑ {format_mbps(up_bps)} / ↓ {format_mbps(down_bps)})"
            )

        self._last_stats_at = float(now)
        self._last_uplink = int(stats.uplink_bytes)
        self._last_downlink = int(stats.downlink_bytes)

    def _on_stats_error(self, token: int, message: str) -> None:
        self._stats_in_flight = False
        if token != self._stats_token:
            return
        # Keep the UI stable; stats may be unavailable if API isn't ready yet.
        logger.info("Stats poll failed: %s", message)

    def _on_ping_clicked(self) -> None:
        if self._ping_in_flight:
            return
        if self._validated_link is None:
            self.diagnostics_widget.set_hint("Validate & Save a link first.")
            return

        link = self._validated_link
        self._ping_in_flight = True
        self.ping_button.setEnabled(False)
        self.diagnostics_widget.set_hint(f"Pinging {link.host}:{link.port} ...")

        def _run():
            return ping_server(
                link.host,
                link.port,
                security=link.security,
                sni=link.sni,
                allow_insecure=link.allow_insecure,
                timeout_s=4.0,
            )

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_ping_result)
        worker.signals.error.connect(self._on_ping_error)
        self._thread_pool.start(worker)

    def _on_ping_result(self, payload: object) -> None:
        self._ping_in_flight = False
        self.ping_button.setEnabled(True)
        if not isinstance(payload, ServerPingResult):  # pragma: no cover - defensive
            self.diagnostics_widget.set_hint("Ping failed: invalid result.")
            return

        parts: list[str] = []
        if payload.tcp_ms is not None:
            parts.append(f"TCP {payload.tcp_ms} ms")
        if payload.tls_sni_ms is not None:
            parts.append(f"TLS(SNI) {payload.tls_sni_ms} ms")
        if payload.tls_host_ms is not None:
            parts.append(f"TLS(host) {payload.tls_host_ms} ms")
        summary = ", ".join(parts) if parts else "No timing data"
        if payload.error:
            summary = f"{summary}. {payload.error}"
        self.diagnostics_widget.set_hint(f"Ping: {summary}")

    def _on_ping_error(self, message: str) -> None:
        self._ping_in_flight = False
        self.ping_button.setEnabled(True)
        self.diagnostics_widget.set_hint(f"Ping failed: {message}")

    def _on_speed_test_clicked(self) -> None:
        if self._speed_test_in_flight:
            return
        if not self._process.is_running():
            self.diagnostics_widget.set_hint("Start the core first.")
            return

        self._speed_test_in_flight = True
        self.speed_test_button.setEnabled(False)
        self.diagnostics_widget.set_hint("Running speed test (download + upload) ...")

        http_port = self._http_port

        def _run():
            return run_speed_test_via_http_proxy(DEFAULT_LISTEN, http_port)

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_speed_test_result)
        worker.signals.error.connect(self._on_speed_test_error)
        self._thread_pool.start(worker)

    def _on_speed_test_result(self, payload: object) -> None:
        self._speed_test_in_flight = False
        self.speed_test_button.setEnabled(True)
        if not isinstance(payload, SpeedTestResult):  # pragma: no cover - defensive
            self.diagnostics_widget.set_hint("Speed test failed: invalid result.")
            return

        if payload.error:
            self.diagnostics_widget.set_hint(f"Speed test failed: {payload.error}")
            return

        down = format_mbps(payload.download_bps or 0.0)
        up = format_mbps(payload.upload_bps or 0.0)
        self.diagnostics_widget.set_hint(f"Speed test: ↓ {down} / ↑ {up}")

    def _on_speed_test_error(self, message: str) -> None:
        self._speed_test_in_flight = False
        self.speed_test_button.setEnabled(True)
        self.diagnostics_widget.set_hint(f"Speed test failed: {message}")

    def _validation_warning(self, link) -> str | None:
        if getattr(link, "security", None) != "tls":
            return None
        if bool(getattr(link, "allow_insecure", False)):
            return None

        host = str(getattr(link, "host", "") or "")
        sni = getattr(link, "sni", None)
        if sni and host and sni != host:
            return (
                "TLS SNI differs from host. Some servers present a certificate for the host even when SNI differs. "
                "If connectivity fails, check logs and try setting `sni` to the host (or set allowInsecure=1 if you understand the risk)."
            )
        return None

    def _kick_health_check(self) -> None:
        if self._health_in_flight:
            return
        if not self._process.is_running():
            return

        token = self._health_token
        http_port = self._http_port
        self._health_in_flight = True

        def _run():
            return token, check_http_proxy(DEFAULT_LISTEN, http_port)

        worker = HealthCheckWorker(_run)
        worker.signals.result.connect(self._on_health_result)
        worker.signals.error.connect(lambda msg: self._on_health_error(token, msg))
        self._thread_pool.start(worker)

    def _on_health_result(self, payload: object) -> None:
        self._health_in_flight = False

        token, result = payload  # type: ignore[misc]
        if token != self._health_token:
            return
        if not isinstance(result, ProxyHealthResult):  # pragma: no cover - defensive
            self._set_health_state("offline", "Health check error")
            return

        if result.state == "online":
            latency = f"{result.latency_ms} ms" if result.latency_ms is not None else "ok"
            self._set_health_state("online", latency)
        elif result.state == "degraded":
            self._set_health_state("degraded", result.error or "Degraded")
        else:
            self._set_health_state("offline", result.error or "Offline")

        ok_now = result.state == "online"
        if self._last_health_ok is True and not ok_now:
            self.diagnostics_widget.set_hint(
                f"Connectivity went offline: {result.error or 'unknown error'}"
            )
        self._last_health_ok = ok_now

    def _on_health_error(self, token: int, message: str) -> None:
        self._health_in_flight = False
        if token != self._health_token:
            return
        self._set_health_state("offline", message)

    def _set_health_state(self, state: str, detail: str) -> None:
        state = state.lower()
        detail = detail.strip() or "—"
        detail_short = detail if len(detail) <= 60 else f"{detail[:57]}…"
        self.health_label.setToolTip(detail)
        if state == "online":
            self.health_label.setText(f"ONLINE ({detail_short})")
            self.health_label.setStyleSheet("color: #2e7d32; font-weight: 600;")
        elif state == "connecting":
            self.health_label.setText(f"CONNECTING ({detail_short})")
            self.health_label.setStyleSheet("color: #546e7a; font-weight: 600;")
        elif state == "degraded":
            self.health_label.setText(f"DEGRADED ({detail_short})")
            self.health_label.setStyleSheet("color: #ef6c00; font-weight: 600;")
        else:
            self.health_label.setText(f"OFFLINE ({detail_short})")
            self.health_label.setStyleSheet("color: #c62828; font-weight: 600;")

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self._process.is_running():
            self._stop_core(user_message="Stopped (app closed).")
        super().closeEvent(event)

    def _apply_system_proxy(self) -> None:
        if self._system_proxy_applied:
            return
        if not self._system_proxy.is_supported():
            self.diagnostics_widget.set_hint(
                "System proxy apply is not supported on this desktop yet. Use manual proxy settings."
            )
            return
        try:
            status = self._system_proxy.apply(
                SystemProxyConfig(
                    http_host=DEFAULT_LISTEN,
                    http_port=int(self._http_port),
                    socks_host=DEFAULT_LISTEN,
                    socks_port=int(self._socks_port),
                    bypass_hosts=["localhost", "127.0.0.0/8", "::1"],
                )
            )
        except AppError as exc:
            self.diagnostics_widget.set_hint(f"Started, but failed to apply system proxy: {exc.user_message}")
            return
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("System proxy apply failed")
            self.diagnostics_widget.set_hint(f"Started, but failed to apply system proxy: {exc}")
            return

        self._system_proxy_applied = True
        self.diagnostics_widget.set_hint(
            "System proxy applied and verified: "
            f"mode={status.mode}, "
            f"http={status.http_host}:{status.http_port} (enabled={status.http_enabled}), "
            f"socks={status.socks_host}:{status.socks_port}."
        )

    def _restore_system_proxy(self) -> str | None:
        if not self._system_proxy_applied and not self._system_proxy.snapshot_path.exists():
            return None
        restore_note: str | None = None
        try:
            status = self._system_proxy.restore()
            restore_note = (
                "System proxy restored: "
                f"mode={status.mode}, "
                f"http={status.http_host}:{status.http_port}, "
                f"socks={status.socks_host}:{status.socks_port}."
            )
        except AppError as exc:
            logger.exception("System proxy restore failed")
            try:
                status = self._system_proxy.force_no_proxy()
                logger.warning("Applied no-proxy fallback after restore failure")
                restore_note = (
                    f"System proxy restore failed ({exc.user_message}); "
                    f"fallback applied: mode={status.mode}."
                )
            except Exception as fallback_exc:
                logger.exception("Failed to apply no-proxy fallback after restore failure")
                restore_note = (
                    f"System proxy restore failed ({exc.user_message}); "
                    f"fallback also failed: {fallback_exc}."
                )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("System proxy restore failed")
            restore_note = f"System proxy restore failed: {exc}."
        self._system_proxy_applied = False
        return restore_note
