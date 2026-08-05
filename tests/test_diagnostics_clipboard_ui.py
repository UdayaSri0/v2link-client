from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_QT_APP = None


def _app():
    global _QT_APP
    from PyQt6.QtWidgets import QApplication

    _QT_APP = QApplication.instance() or _QT_APP or QApplication([])
    return _QT_APP


def _diagnostics_widget(monkeypatch):
    from v2link_client.ui.diagnostics_widget import DiagnosticsWidget

    _app()
    monkeypatch.setattr(DiagnosticsWidget, "refresh", lambda _self: None)
    return DiagnosticsWidget()


def test_diagnostics_actions_exist_and_fit_small_layout(monkeypatch) -> None:
    from PyQt6.QtWidgets import QGridLayout

    widget = _diagnostics_widget(monkeypatch)
    widget.resize(640, 520)
    widget.show()
    _app().processEvents()

    labels = {
        widget.refresh_button.text(),
        widget.copy_button.text(),
        widget.copy_latest_error_button.text(),
        widget.save_button.text(),
        widget.open_logs_button.text(),
        widget.copy_manual_button.text(),
    }
    assert labels == {
        "Refresh",
        "Copy diagnostics report",
        "Copy latest error",
        "Save diagnostics report",
        "Open logs folder",
        "Copy manual proxy settings",
    }
    action_layout = widget.layout().itemAt(1).layout()
    assert isinstance(action_layout, QGridLayout)
    assert action_layout.rowCount() == 2
    assert all(button.isVisible() for button in (widget.refresh_button, widget.copy_button, widget.copy_latest_error_button))
    assert widget.copy_latest_error_button.accessibleName() == "Copy latest error"
    widget.close()


def test_diagnostics_result_display_copy_and_save_are_identically_sanitized(
    tmp_path, monkeypatch
) -> None:
    import v2link_client.ui.diagnostics_widget as diagnostics_ui

    app = _app()
    widget = _diagnostics_widget(monkeypatch)
    raw = (
        "Xray 26.3.27\n"
        "vless://11111111-1111-1111-1111-111111111111@example.invalid:443?token=secret"
    )
    widget._refresh_generation = 4
    widget._on_result(4, raw)
    displayed = widget.text_area.toPlainText()

    widget.copy_report()
    destination = tmp_path / "diagnostics.txt"
    monkeypatch.setattr(
        diagnostics_ui.QFileDialog,
        "getSaveFileName",
        lambda *_args, **_kwargs: (str(destination), "Text files (*.txt)"),
    )
    widget.save_report()

    assert displayed == app.clipboard().text()
    assert displayed == destination.read_text(encoding="utf-8")
    assert "Xray 26.3.27" in displayed
    assert "vless://<redacted>" in displayed
    assert "11111111-1111-1111-1111-111111111111" not in displayed
    assert widget.hint_label.text() == "Diagnostics report saved successfully."
    widget.close()


def test_latest_error_copy_success_and_empty_state(monkeypatch) -> None:
    app = _app()
    widget = _diagnostics_widget(monkeypatch)
    widget.set_latest_error_provider(
        lambda: "Xray startup failed: password=synthetic-secret\nHTTP 403"
    )

    widget.copy_latest_error()

    assert "synthetic-secret" not in app.clipboard().text()
    assert "password=<redacted>" in app.clipboard().text()
    assert "HTTP 403" in app.clipboard().text()
    assert widget.hint_label.text() == "Latest error copied successfully."

    widget.set_latest_error_provider(lambda: None)
    widget.copy_latest_error()
    assert widget.hint_label.text() == "No recent error is available to copy."
    widget.close()


def test_refresh_uses_current_error_instead_of_stale_runtime_snapshot(
    monkeypatch,
) -> None:
    import v2link_client.ui.diagnostics_widget as diagnostics_ui

    original_refresh = diagnostics_ui.DiagnosticsWidget.refresh
    widget = _diagnostics_widget(monkeypatch)
    monkeypatch.setattr(diagnostics_ui.DiagnosticsWidget, "refresh", original_refresh)
    captured: dict[str, object] = {}

    def collect(*, state):
        captured["state"] = state
        return "synthetic diagnostics"

    monkeypatch.setattr(diagnostics_ui, "collect_diagnostics", collect)
    widget.thread_pool = SimpleNamespace(start=lambda worker: worker.run())
    widget.set_runtime_state({"recent_error": {"summary": "stale error"}})
    widget.set_latest_error_state_provider(
        lambda: {
            "source": "Xray startup",
            "summary": "current error",
            "details": "safe detail",
            "timestamp": "2026-08-05T10:00:00+00:00",
            "severity": "error",
            "reason_code": "startup-failed",
        }
    )

    widget.refresh()
    _app().processEvents()

    state = captured["state"]
    assert isinstance(state, dict)
    assert state["recent_error"]["summary"] == "current error"
    assert widget.text_area.toPlainText() == "synthetic diagnostics"
    widget.close()


def test_diagnostics_save_cancel_and_failure_are_confirmed(tmp_path, monkeypatch) -> None:
    import v2link_client.ui.diagnostics_widget as diagnostics_ui

    widget = _diagnostics_widget(monkeypatch)
    widget.text_area.setPlainText("sanitized report")
    monkeypatch.setattr(
        diagnostics_ui.QFileDialog,
        "getSaveFileName",
        lambda *_args, **_kwargs: ("", ""),
    )

    widget.save_report()
    assert widget.hint_label.text() == "Save cancelled."

    monkeypatch.setattr(
        diagnostics_ui.QFileDialog,
        "getSaveFileName",
        lambda *_args, **_kwargs: (str(tmp_path), "Text files (*.txt)"),
    )
    widget.save_report()
    assert widget.hint_label.text() == "Could not save diagnostics report."
    widget.close()


def test_refresh_state_and_shutdown_ignore_stale_result(monkeypatch) -> None:
    widget = _diagnostics_widget(monkeypatch)
    widget._refresh_generation = 2
    widget.text_area.setPlainText("existing")
    widget.shutdown()

    widget._on_result(2, "replacement")

    assert widget.text_area.toPlainText() == "existing"
    widget.close()


def test_profile_validation_error_copy_and_success_clear(monkeypatch) -> None:
    from v2link_client.ui.profile_dialogs import ProfileEditorDialog

    app = _app()
    raw_error = (
        "Xray rejected vless://11111111-1111-1111-1111-111111111111@example.invalid"
    )
    results = iter([(False, raw_error), (True, "Valid: Synthetic profile")])
    dialog = ProfileEditorDialog(validate_fn=lambda _url: next(results))
    dialog.url_input.setText(
        "vless://22222222-2222-2222-2222-222222222222@example.invalid"
    )

    dialog._on_validate_clicked()
    assert dialog.copy_validation_error_button.isEnabled()
    assert not dialog.copy_validation_error_button.isHidden()
    assert "11111111-1111-1111-1111-111111111111" not in dialog.validation_label.text()
    dialog.resize(480, 360)
    dialog.show()
    app.processEvents()
    assert dialog.copy_validation_error_button.isVisible()

    dialog._copy_validation_error()
    copied = app.clipboard().text()
    assert "Category: profile validation" in copied
    assert "vless://<redacted>" in copied
    assert "11111111-1111-1111-1111-111111111111" not in copied
    assert "22222222-2222-2222-2222-222222222222" not in copied
    assert dialog.validation_copy_hint.text() == (
        "Profile validation error copied successfully."
    )

    dialog._on_validate_clicked()
    assert not dialog.copy_validation_error_button.isEnabled()
    assert dialog.copy_validation_error_button.isHidden()
    assert dialog._validation_error_text is None
    dialog.close()


def test_profile_warning_only_does_not_enable_error_copy() -> None:
    from v2link_client.ui.profile_dialogs import ProfileEditorDialog

    _app()
    dialog = ProfileEditorDialog(
        validate_fn=lambda _url: (
            True,
            "Valid: Synthetic profile\nWarning: secure certificate verification is used.",
        )
    )
    dialog.url_input.setText("vless://synthetic@example.invalid")

    dialog._on_validate_clicked()

    assert not dialog.copy_validation_error_button.isEnabled()
    assert dialog.copy_validation_error_button.isHidden()
    assert "Warning:" in dialog.validation_label.text()
    dialog.close()


def test_profile_clipboard_failure_is_presented(monkeypatch) -> None:
    import v2link_client.ui.profile_dialogs as profile_ui
    from v2link_client.ui.safe_text_actions import TextActionResult

    _app()
    dialog = profile_ui.ProfileEditorDialog(
        validate_fn=lambda _url: (False, "Synthetic validation failure")
    )
    dialog.url_input.setText("vless://synthetic@example.invalid")
    dialog._on_validate_clicked()
    monkeypatch.setattr(
        profile_ui,
        "copy_sanitized_text",
        lambda *_args, **_kwargs: TextActionResult(
            False, "Could not copy profile validation error."
        ),
    )

    dialog._copy_validation_error()

    assert dialog.validation_copy_hint.text() == (
        "Could not copy profile validation error."
    )
    dialog.close()


def test_helper_diagnostics_copy_uses_structured_safe_text() -> None:
    from v2link_client.ui.traffic_monitor_widget import TrafficMonitorWidget
    from PyQt6.QtWidgets import QLabel

    app = _app()
    harness = SimpleNamespace(
        app_status_label=QLabel(),
        _netmon_status=SimpleNamespace(
            installed=True,
            running=True,
            operational=False,
            installation_state="installed",
            daemon_state="reachable",
            backend_state="not-implemented",
            reason_code="backend-not-implemented",
            backend="ebpf-unavailable",
            service_state="active",
            socket_path="/run/v2link-client/netmon.sock",
            kernel_supported=False,
            last_response="status ok",
            last_error="password=synthetic-secret",
            remediation="Backend unavailable in this release.",
        )
    )

    TrafficMonitorWidget._copy_helper_diagnostics(harness)
    copied = app.clipboard().text()

    assert "helper_operational=False" in copied
    assert "backend-not-implemented" in copied
    assert "service_state=active" in copied
    assert "kernel_supported=False" in copied
    assert "password=<redacted>" in copied
    assert "synthetic-secret" not in copied
    assert harness.app_status_label.text() == "Helper diagnostics copied successfully."
