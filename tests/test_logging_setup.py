from __future__ import annotations

import logging

import pytest

import v2link_client.core.logging_setup as logging_setup


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("profile vless://test-user@example.invalid:443?token=synthetic", "test-user"),
        ("identity 123e4567-e89b-42d3-a456-426614174000", "123e4567"),
        ("identity 11111111-1111-1111-1111-111111111111", "11111111"),
        ("contact synthetic.user@example.invalid", "synthetic.user"),
        ("password=synthetic-password", "synthetic-password"),
        ("token:synthetic-token", "synthetic-token"),
        ("authorization=synthetic-auth", "synthetic-auth"),
        ("path /home/synthetic-user/.config/v2link-client", "synthetic-user"),
        ("pin " + "a5" * 32, "a5" * 32),
        ("pin " + ":".join(["A5"] * 32), ":".join(["A5"] * 32)),
        (
            "-----BEGIN CERTIFICATE-----\nsynthetic-body\n-----END CERTIFICATE-----",
            "synthetic-body",
        ),
        ("upstream synthetic-user:synthetic-pass@example.invalid", "synthetic-pass"),
    ],
)
def test_sensitive_text_sanitizer_removes_synthetic_secrets(raw: str, secret: str) -> None:
    sanitized = logging_setup.sanitize_sensitive_text(raw)

    assert secret not in sanitized
    assert sanitized != raw


def test_sensitive_text_sanitizer_preserves_xray_error_reason_and_field_name() -> None:
    raw = "transport/internet: invalid pinnedPeerCertSha256: certificate hash has wrong length"

    assert logging_setup.sanitize_sensitive_text(raw) == raw


def test_sensitive_text_sanitizer_handles_malformed_url_port() -> None:
    sanitized = logging_setup.sanitize_sensitive_text(
        "Xray rejected vless://synthetic-user@example.invalid:not-a-port"
    )

    assert sanitized == "Xray rejected vless://<redacted>"


def test_python_log_rotation_is_bounded(tmp_path, monkeypatch) -> None:
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    for handler in original_handlers:
        root.removeHandler(handler)
    monkeypatch.setattr(logging_setup, "get_logs_dir", lambda: tmp_path)
    monkeypatch.setattr(logging_setup, "MAX_LOG_BYTES", 256)
    monkeypatch.setattr(logging_setup, "BACKUP_COUNT", 2)
    try:
        path = logging_setup.setup_logging()
        for index in range(100):
            logging.getLogger("rotation-test").warning("event=%s %s", index, "x" * 40)
        for handler in list(root.handlers):
            handler.flush()

        files = list(tmp_path.glob("app.log*"))
        assert path in files
        assert len(files) <= 3
        assert all(file.stat().st_size <= 512 for file in files)
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
            handler.close()
        for handler in original_handlers:
            root.addHandler(handler)
