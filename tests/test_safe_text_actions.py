from __future__ import annotations

from datetime import datetime, timezone
import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_QT_APP = None


def _app():
    global _QT_APP
    from PyQt6.QtWidgets import QApplication

    _QT_APP = QApplication.instance() or _QT_APP or QApplication([])
    return _QT_APP


def test_copy_sanitizes_content_and_preserves_line_breaks() -> None:
    from v2link_client.ui.safe_text_actions import copy_sanitized_text

    app = _app()
    result = copy_sanitized_text(
        "first line\nvless://11111111-1111-1111-1111-111111111111@example.invalid:443?token=secret",
        label="diagnostics report",
    )

    copied = app.clipboard().text()
    assert result.succeeded is True
    assert result.message == "Diagnostics report copied successfully."
    assert copied.startswith("first line\n")
    assert "vless://<redacted>" in copied
    assert "11111111-1111-1111-1111-111111111111" not in copied
    assert "token=secret" not in copied


def test_copy_handles_empty_text_and_missing_application(monkeypatch) -> None:
    import v2link_client.ui.safe_text_actions as actions

    empty = actions.copy_sanitized_text("", label="latest error")
    assert empty.succeeded is False
    assert empty.message == "No latest error is available to copy."

    monkeypatch.setattr(actions, "QApplication", SimpleNamespace(instance=lambda: None))
    unavailable = actions.copy_sanitized_text("safe details", label="latest error")
    assert unavailable.succeeded is False
    assert "clipboard is unavailable" in unavailable.message


def test_copy_handles_clipboard_exception_without_logging_content(monkeypatch, caplog) -> None:
    import v2link_client.ui.safe_text_actions as actions

    class BrokenClipboard:
        def setText(self, _text):  # noqa: ANN001, N802
            raise RuntimeError("synthetic clipboard failure")

    fake_app = SimpleNamespace(clipboard=lambda: BrokenClipboard())
    monkeypatch.setattr(actions, "QApplication", SimpleNamespace(instance=lambda: fake_app))
    secret = "vless://11111111-1111-1111-1111-111111111111@example.invalid"

    result = actions.copy_sanitized_text(secret, label="profile validation error")

    assert result.succeeded is False
    assert "Could not copy" in result.message
    assert secret not in caplog.text


def test_copy_enforces_export_limit() -> None:
    from v2link_client.core.logging_setup import MAX_EXPORT_BYTES
    from v2link_client.ui.safe_text_actions import copy_sanitized_text

    app = _app()
    result = copy_sanitized_text("✓" * MAX_EXPORT_BYTES, label="diagnostics report")

    copied = app.clipboard().text()
    assert result.succeeded is True
    assert len(copied.encode("utf-8")) <= MAX_EXPORT_BYTES
    assert "[report truncated after" in copied


def test_copy_and_save_block_adversarial_secret_encodings(tmp_path) -> None:
    from v2link_client.ui.safe_text_actions import (
        copy_sanitized_text,
        save_sanitized_text,
    )

    app = _app()
    raw = "\n".join(
        (
            "V2LINK_PASSWORD=SYNTH_ENV_SECRET",
            'tool --password "SYNTH QUOTED SECRET" --port 1080',
            "https%3A%2F%2Fuser%3ASYNTH_ENCODED_SECRET%40example.invalid",
            "pinnedPeerCertSha256=QWERTYuiopASDFGHjklZXCVBnm1234567890abcdEFG=",
        )
    )
    destination = tmp_path / "safe.txt"

    assert copy_sanitized_text(raw, label="diagnostics report").succeeded
    assert save_sanitized_text(
        destination, raw, label="diagnostics report"
    ).succeeded

    copied = app.clipboard().text()
    saved = destination.read_text(encoding="utf-8")
    assert copied == saved
    for secret in (
        "SYNTH_ENV_SECRET",
        "SYNTH QUOTED SECRET",
        "SYNTH_ENCODED_SECRET",
        "QWERTYuiopASDFGHjklZXCVBnm1234567890abcdEFG=",
    ):
        assert secret not in copied
    assert "pinnedPeerCertSha256" in copied
    assert "port 1080" in copied


def test_save_sanitized_utf8_and_safe_filename(tmp_path) -> None:
    from v2link_client.ui.safe_text_actions import (
        diagnostics_filename,
        save_sanitized_text,
    )

    destination = tmp_path / "report.txt"
    raw = "Unicode ✓\npassword=synthetic-secret"
    result = save_sanitized_text(destination, raw, label="diagnostics report")

    assert result.succeeded is True
    saved = destination.read_text(encoding="utf-8")
    assert saved == "Unicode ✓\npassword=<redacted>"
    assert "synthetic-secret" not in saved
    assert diagnostics_filename(datetime(2026, 8, 5, 7, 8, 9, tzinfo=timezone.utc)) == (
        "v2link-client-diagnostics-20260805-070809.txt"
    )


def test_save_handles_cancel_empty_and_write_failure(tmp_path) -> None:
    from v2link_client.ui.safe_text_actions import save_sanitized_text

    cancelled = save_sanitized_text("", "report", label="diagnostics report")
    empty = save_sanitized_text(tmp_path / "empty.txt", "", label="diagnostics report")
    failed = save_sanitized_text(tmp_path, "report", label="diagnostics report")

    assert cancelled.cancelled is True
    assert empty.succeeded is False
    assert "available" in empty.message
    assert failed.succeeded is False
    assert failed.message == "Could not save diagnostics report."
