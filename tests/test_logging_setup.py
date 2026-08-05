from __future__ import annotations

import logging
import time

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


@pytest.mark.parametrize(
    ("raw", "forbidden", "preserved"),
    [
        (
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.invalid:443?token=fixture",
            "01234567-89ab",
            "vless://<redacted>",
        ),
        ("vmess://c3ludGhldGljLWZpeHR1cmU=", "c3ludGhldGlj", "vmess://<redacted>"),
        ("trojan://fixture-pass@example.invalid:443", "fixture-pass", "trojan://<redacted>"),
        ("ss://fixture-secret@example.invalid:8388", "fixture-secret", "ss://<redacted>"),
        (
            "http://fixture-user:fixture-pass@proxy.invalid:8080/path",
            "fixture-pass",
            "proxy.invalid:8080",
        ),
        (
            "socks5://fixture-user:fixture-pass@127.0.0.1:1080",
            "fixture-pass",
            "socks5://<redacted>",
        ),
        (
            "https://subscription.invalid/fetch?access_token=fixture-token",
            "fixture-token",
            "subscription.invalid",
        ),
        ("Authorization: Bearer fixture.token.value", "fixture.token.value", "Authorization"),
        ("X-Api-Key: fixture-api-key", "fixture-api-key", "X-Api-Key"),
        ("Cookie: session=fixture-cookie", "fixture-cookie", "Cookie"),
        ("synthetic-tool --token fixture-cli-token --port 1080", "fixture-cli-token", "port 1080"),
        (
            'synthetic-tool --password "fixture quoted secret" --port 1080',
            "fixture quoted secret",
            "port 1080",
        ),
        ("V2LINK_PASSWORD=SYNTH_ENV_SECRET", "SYNTH_ENV_SECRET", "V2LINK_PASSWORD"),
        (
            "https%3A%2F%2Fuser%3Afixture-encoded-secret%40subscription.invalid%2Ffetch",
            "fixture-encoded-secret",
            "<redacted-url>",
        ),
        (
            "pinnedPeerCertSha256=QWERTYuiopASDFGHjklZXCVBnm1234567890abcdEFG=",
            "QWERTYuiopASDFGHjklZXCVBnm1234567890abcdEFG=",
            "pinnedPeerCertSha256",
        ),
        ('{"session_id": "fixture-session"}', "fixture-session", "session_id"),
        ("contact δοκιμή@example.invalid", "δοκιμή", "<redacted-email>"),
        ("{'password': 'fixture password'}", "fixture password", "password"),
        (
            "org.gnome.system.proxy.http authentication-user 'fixture-user'",
            "fixture-user",
            "authentication-user",
        ),
        (
            "org.gnome.system.proxy.http authentication-password 'fixture-pass'",
            "fixture-pass",
            "authentication-password",
        ),
        (
            "-----BEGIN PRIVATE KEY-----\nfixture-private-body\n-----END PRIVATE KEY-----",
            "fixture-private-body",
            "<redacted>",
        ),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nfixture-rsa-body\n-----END RSA PRIVATE KEY-----",
            "fixture-rsa-body",
            "<redacted>",
        ),
        (
            "-----BEGIN CERTIFICATE-----\nfixture-unterminated-body",
            "fixture-unterminated-body",
            "<redacted>",
        ),
        (
            "file:///home/fixture-user/Documents/report.txt",
            "fixture-user",
            "/home/<user>/Documents/report.txt",
        ),
        (
            "failure for /home/δοκιμή/.config and malformed https://invalid.invalid/%ZZ?token=fixture",
            "δοκιμή",
            "/home/<user>/",
        ),
    ],
)
def test_sensitive_text_sanitizer_covers_export_secret_categories(
    raw: str, forbidden: str, preserved: str
) -> None:
    sanitized = logging_setup.sanitize_sensitive_text(raw)

    assert forbidden not in sanitized
    assert preserved in sanitized
    assert logging_setup.sanitize_sensitive_text(sanitized) == sanitized


@pytest.mark.parametrize(
    "technical_detail",
    [
        "Xray 26.3.27",
        "pinnedPeerCertSha256",
        "verifyPeerCertByName",
        "backend-not-implemented",
        "/usr/lib/v2link-client/v2link-netmon",
        "/run/v2link-client/netmon.sock",
        "localhost 127.0.0.1 HTTP 403 port 1080",
        "service inactive Linux 6.8.0 amd64",
        "installed=true running=true operational=false",
    ],
)
def test_sensitive_text_sanitizer_preserves_useful_diagnostics(
    technical_detail: str,
) -> None:
    assert logging_setup.sanitize_sensitive_text(technical_detail) == technical_detail


def test_sensitive_text_sanitizer_accepts_none_and_unusual_unicode() -> None:
    assert logging_setup.sanitize_sensitive_text(None) == ""
    assert logging_setup.sanitize_sensitive_text("failure — λ 🚦") == "failure — λ 🚦"


def test_export_limit_is_sanitized_explicit_and_utf8_safe() -> None:
    raw = ("λ🚦" * 200) + " password=fixture-secret"

    limited = logging_setup.limit_export_text(raw, max_bytes=128)

    assert len(limited.encode("utf-8")) <= 128
    assert "[report truncated after 128 bytes]" in limited
    assert "fixture-secret" not in limited
    limited.encode("utf-8").decode("utf-8")


def test_representative_large_multiline_input_is_deterministic() -> None:
    raw = ("component=transport backend-not-implemented token=fixture\n" * 10_000)

    first = logging_setup.limit_export_text(raw)
    second = logging_setup.limit_export_text(raw)

    assert first == second
    assert "fixture" not in first
    assert "backend-not-implemented" in first


def test_large_nonmatching_unicode_input_has_bounded_runtime() -> None:
    raw = "✓" * 262_144

    started = time.perf_counter()
    sanitized = logging_setup.sanitize_sensitive_text(raw)
    elapsed = time.perf_counter() - started

    assert sanitized == raw
    assert elapsed < 3.0


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


def test_logging_boundary_sanitizes_messages_arguments_and_tracebacks(
    tmp_path, monkeypatch
) -> None:
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    for handler in original_handlers:
        root.removeHandler(handler)
    monkeypatch.setattr(logging_setup, "get_logs_dir", lambda: tmp_path)
    try:
        path = logging_setup.setup_logging()
        secret_url = (
            "vless://11111111-1111-1111-1111-111111111111@"
            "example.invalid?token=fixture-log-secret"
        )
        logging.getLogger("privacy-boundary").error("failure %s", secret_url)
        try:
            raise RuntimeError(f"traceback contained {secret_url}")
        except RuntimeError:
            logging.getLogger("privacy-boundary").exception("operation failed")
        for handler in list(root.handlers):
            handler.flush()

        logged = path.read_text(encoding="utf-8")
        assert "fixture-log-secret" not in logged
        assert "11111111-1111-1111-1111-111111111111" not in logged
        assert "vless://<redacted>" in logged
        assert "RuntimeError" in logged
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
            handler.close()
        for handler in original_handlers:
            root.addHandler(handler)
