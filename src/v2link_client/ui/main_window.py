"""Main application window."""

from __future__ import annotations

import logging

from PyQt6.QtCore import QObject, QRunnable, Qt, QThreadPool, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from v2link_client.core.config_builder import (
    DEFAULT_HTTP_PORT,
    DEFAULT_LISTEN,
    DEFAULT_SOCKS_PORT,
    build_xray_config,
)
from v2link_client.core.errors import AppError
from v2link_client.core.health_check import ProxyHealthResult, check_http_proxy
from v2link_client.core.link_parser import parse_link
from v2link_client.core.process_manager import (
    XrayProcessManager,
    ensure_port_available,
    find_free_port,
    find_xray_binary,
    validate_xray_config,
)
from v2link_client.core.storage import get_config_dir, get_state_dir, load_json, save_json
from v2link_client.ui.diagnostics_widget import DiagnosticsWidget

logger = logging.getLogger(__name__)

PROFILE_FILE = "profile.json"
XRAY_CONFIG_FILE = "xray_config.json"

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

        central = QWidget(self)
        self.setCentralWidget(central)

        self.link_input = QLineEdit()
        self.link_input.setPlaceholderText("Paste a vless:// link")

        self.validate_button = QPushButton("Validate & Save")
        self.validate_button.clicked.connect(self._on_validate_clicked)

        self.start_stop_button = QPushButton("Start")
        self.start_stop_button.setEnabled(False)
        self.start_stop_button.clicked.connect(self._on_start_stop_clicked)

        self.status_label = QLabel("STOPPED")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        self.health_label = QLabel("OFFLINE")
        self.health_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._set_health_state("offline", "Not running")

        top_row = QHBoxLayout()
        top_row.addWidget(self.link_input, 1)
        top_row.addWidget(self.validate_button)

        control_row = QHBoxLayout()
        control_row.addWidget(self.start_stop_button)
        control_row.addWidget(QLabel("Status:"))
        control_row.addWidget(self.status_label, 1)
        control_row.addWidget(QLabel("Connectivity:"))
        control_row.addWidget(self.health_label)

        self.diagnostics_widget = DiagnosticsWidget()

        layout = QVBoxLayout()
        layout.addLayout(top_row)
        layout.addLayout(control_row)
        layout.addWidget(self.diagnostics_widget, 1)

        central.setLayout(layout)

        self._process = XrayProcessManager()
        self._validated_config_path = None
        self._validated_link = None
        self._socks_port = DEFAULT_SOCKS_PORT
        self._http_port = DEFAULT_HTTP_PORT
        self.diagnostics_widget.set_proxy_ports(
            socks_port=self._socks_port, http_port=self._http_port
        )
        self._thread_pool = QThreadPool.globalInstance()

        self._health_timer = QTimer(self)
        self._health_timer.setInterval(HEALTH_INTERVAL_MS)
        self._health_timer.timeout.connect(self._kick_health_check)
        self._health_in_flight = False
        self._health_token = 0
        self._last_health_ok: bool | None = None

        self._status_timer = QTimer(self)
        self._status_timer.setInterval(1000)
        self._status_timer.timeout.connect(self._poll_core_status)

        self._load_profile()

    def _on_validate_clicked(self) -> None:
        self.status_label.setText("STOPPED")
        self._validated_config_path = None
        self._validated_link = None
        self.start_stop_button.setEnabled(False)

        raw_link = self.link_input.text()
        try:
            parsed_link = parse_link(raw_link)
            socks_port, http_port = self._pick_proxy_ports()
            config = build_xray_config(
                parsed_link, socks_port=socks_port, http_port=http_port
            )
            config_path = get_state_dir() / XRAY_CONFIG_FILE
            save_json(config_path, config)

            profile_path = get_config_dir() / PROFILE_FILE
            save_json(profile_path, {"link": raw_link})

            xray = find_xray_binary()
            validate_xray_config(xray, config_path)
        except AppError as exc:
            self.diagnostics_widget.set_hint(exc.user_message)
            return
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Validation failed")
            self.diagnostics_widget.set_hint(f"Validation failed: {exc}")
            return

        self._process = XrayProcessManager(xray)
        self._validated_config_path = config_path
        self._validated_link = parsed_link
        self._socks_port = socks_port
        self._http_port = http_port
        self.diagnostics_widget.set_proxy_ports(
            socks_port=self._socks_port, http_port=self._http_port
        )
        self.start_stop_button.setEnabled(True)
        hint = (
            f"Validated: {parsed_link.display_name()}. "
            f"Ready to start (SOCKS5 {DEFAULT_LISTEN}:{self._socks_port}, HTTP {DEFAULT_LISTEN}:{self._http_port})."
        )
        warning = self._validation_warning(parsed_link)
        if warning:
            hint = f"{hint}  Warning: {warning}"
        self.diagnostics_widget.set_hint(hint)
        self._set_health_state("offline", "Not running")

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
        self.link_input.setEnabled(False)
        self.validate_button.setEnabled(False)
        self._health_token += 1
        self._last_health_ok = None
        self._set_health_state("connecting", "Checking…")
        self._health_timer.start()
        self._kick_health_check()
        self.diagnostics_widget.set_hint(
            f"Started Xray. SOCKS5 {DEFAULT_LISTEN}:{self._socks_port} / HTTP {DEFAULT_LISTEN}:{self._http_port}"
        )
        self._status_timer.start()

    def _poll_core_status(self) -> None:
        if self._process.is_running():
            return

        code = self._process.returncode()
        self._status_timer.stop()
        self.status_label.setText("STOPPED")
        self.start_stop_button.setText("Start")
        self.link_input.setEnabled(True)
        self.validate_button.setEnabled(True)
        self._health_timer.stop()
        self._health_token += 1
        self._set_health_state("offline", "Not running")

        suffix = f" (exit code {code})" if code is not None else ""
        hint = f"Core stopped{suffix}. Check logs for details."
        if self._process.stdout_path:
            hint = f"Core stopped{suffix}. Logs: {self._process.stdout_path}"
        self.diagnostics_widget.set_hint(hint)

    def _stop_core(self, *, user_message: str) -> None:
        self._status_timer.stop()
        self._health_timer.stop()
        self._health_token += 1
        try:
            self._process.stop()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Stop failed")

        self.status_label.setText("STOPPED")
        self.start_stop_button.setText("Start")
        self.link_input.setEnabled(True)
        self.validate_button.setEnabled(True)
        self._set_health_state("offline", "Not running")
        self.diagnostics_widget.set_hint(user_message)

    def _load_profile(self) -> None:
        profile_path = get_config_dir() / PROFILE_FILE
        data = load_json(profile_path, {})
        if isinstance(data, dict):
            link = data.get("link")
            if isinstance(link, str) and link.strip():
                self.link_input.setText(link)

    def _pick_proxy_ports(self) -> tuple[int, int]:
        socks_port = DEFAULT_SOCKS_PORT
        http_port = DEFAULT_HTTP_PORT

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

        return socks_port, http_port

    def _validation_warning(self, link) -> str | None:
        if getattr(link, "security", None) != "tls":
            return None
        if bool(getattr(link, "allow_insecure", False)):
            return None

        host = str(getattr(link, "host", "") or "")
        sni = getattr(link, "sni", None)
        if sni and host and sni != host:
            return (
                "TLS SNI differs from host. With allowInsecure=0 the certificate must match SNI. "
                "If connectivity fails, try removing `sni` or setting it to the host."
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
