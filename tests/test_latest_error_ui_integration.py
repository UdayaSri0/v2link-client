from __future__ import annotations

import logging
from types import SimpleNamespace

from v2link_client.core.errors import ConfigBuildError, InvalidLinkError
from v2link_client.core.latest_error import LatestErrorStore
from v2link_client.ui.main_window import (
    ERROR_SOURCE_NETMON,
    ERROR_SOURCE_PROFILE_IMPORT,
    ERROR_SOURCE_XRAY_VALIDATION,
    MainWindow,
)


def _window(**values):
    defaults = {
        "_latest_errors": LatestErrorStore(),
        "_validation_warning": lambda _parsed: None,
        "_profile_store": SimpleNamespace(
            find_by_url=lambda _raw: None,
        ),
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def test_latest_error_provider_returns_none_until_an_active_error_exists() -> None:
    window = _window()

    assert MainWindow._latest_error_text(window) is None

    MainWindow._record_latest_error(
        window,
        ERROR_SOURCE_XRAY_VALIDATION,
        "Synthetic validation failure.",
        details="field pinnedPeerCertSha256 was rejected",
        reason_code="synthetic-failure",
    )

    text = MainWindow._latest_error_text(window)
    assert text is not None
    assert "Source: Xray validation" in text
    assert "Reason code: synthetic-failure" in text
    assert "pinnedPeerCertSha256" in text
    state = MainWindow._latest_error_state(window)
    assert state is not None
    assert state["source"] == ERROR_SOURCE_XRAY_VALIDATION
    assert state["reason_code"] == "synthetic-failure"


def test_dialog_validation_failure_is_sanitized_before_latest_error_storage() -> None:
    secret_url = "vless://11111111-1111-1111-1111-111111111111@example.invalid?token=secret"

    def fail(_raw, *, persist_runtime_config):
        assert persist_runtime_config is False
        raise ConfigBuildError(
            "synthetic",
            user_message=f"Xray rejected config from {secret_url}",
        )

    window = _window(_validate_link=fail)

    ok, message = MainWindow._validate_link_for_dialog(window, secret_url)

    assert ok is False
    assert secret_url not in message
    retained = window._latest_errors.latest_active()
    assert retained is not None
    assert retained.source == ERROR_SOURCE_XRAY_VALIDATION
    assert secret_url not in retained.details
    assert "11111111-1111-1111-1111-111111111111" not in retained.details
    assert "secret" not in retained.details


def test_profile_parse_failure_uses_profile_import_category() -> None:
    window = _window(
        _validate_link=lambda _raw, *, persist_runtime_config: (_ for _ in ()).throw(
            InvalidLinkError("bad link", user_message="The imported profile is malformed.")
        )
    )

    ok, _message = MainWindow._validate_link_for_dialog(window, "synthetic")

    assert ok is False
    assert window._latest_errors.latest_active().source == ERROR_SOURCE_PROFILE_IMPORT


def test_unexpected_validation_error_is_not_logged_raw(caplog) -> None:
    secret = "user@example.invalid token=synthetic-secret"
    window = _window(
        _validate_link=lambda _raw, *, persist_runtime_config: (_ for _ in ()).throw(
            RuntimeError(secret)
        )
    )

    with caplog.at_level(logging.ERROR):
        ok, message = MainWindow._validate_link_for_dialog(window, "synthetic")

    assert ok is False
    assert secret not in message
    assert secret not in caplog.text
    assert "synthetic-secret" not in caplog.text


def test_successful_validation_clears_only_validation_categories() -> None:
    parsed = SimpleNamespace(display_name=lambda: "Synthetic profile")
    window = _window(
        _validate_link=lambda _raw, *, persist_runtime_config: (
            parsed,
            None,
            None,
            0,
            0,
            0,
        )
    )
    window._latest_errors.record(ERROR_SOURCE_PROFILE_IMPORT, "old import error")
    window._latest_errors.record(ERROR_SOURCE_XRAY_VALIDATION, "old validation error")
    window._latest_errors.record("System proxy", "unrelated active error")

    ok, message = MainWindow._validate_link_for_dialog(window, "synthetic")

    assert ok is True
    assert message == "Valid: Synthetic profile"
    latest = window._latest_errors.latest_active()
    assert latest is not None
    assert latest.source == "System proxy"


def test_warning_only_validation_does_not_create_latest_error() -> None:
    parsed = SimpleNamespace(display_name=lambda: "Synthetic profile")
    window = _window(
        _validate_link=lambda _raw, *, persist_runtime_config: (
            parsed,
            None,
            None,
            0,
            0,
            0,
        ),
        _validation_warning=lambda _parsed: "Compatibility warning only.",
    )

    ok, message = MainWindow._validate_link_for_dialog(window, "synthetic")

    assert ok is True
    assert "Warning: Compatibility warning only." in message
    assert window._latest_errors.latest_active() is None


def test_normal_optional_netmon_states_do_not_become_errors() -> None:
    window = _window()
    for state in (
        {"reason_code": "tracking-disabled", "backend_state": "unavailable"},
        {"reason_code": "helper-not-installed", "backend_state": "unknown"},
        {"reason_code": "external-helper-required", "backend_state": "unavailable"},
        {"reason_code": "backend-not-implemented", "backend_state": "not-implemented"},
    ):
        MainWindow._sync_netmon_latest_error(window, state)
        assert window._latest_errors.latest_active() is None


def test_structured_netmon_failure_becomes_sanitized_error_then_clears() -> None:
    window = _window()
    MainWindow._sync_netmon_latest_error(
        window,
        {
            "reason_code": "permission-denied",
            "daemon_state": "permission-denied",
            "backend_state": "unknown",
            "message": "Helper access was denied.",
            "last_error": (
                "failed for user@example.invalid and "
                "vless://11111111-1111-1111-1111-111111111111@example.invalid"
            ),
            "remediation": "Ask an administrator to grant group access.",
        },
    )

    retained = window._latest_errors.latest_active()
    assert retained is not None
    assert retained.source == ERROR_SOURCE_NETMON
    assert retained.reason_code == "permission-denied"
    assert "user@example.invalid" not in retained.details
    assert "11111111-1111-1111-1111-111111111111" not in retained.details
    assert "vless://11111111" not in retained.details

    MainWindow._sync_netmon_latest_error(
        window,
        {"reason_code": "backend-not-implemented", "backend_state": "not-implemented"},
    )
    assert window._latest_errors.latest_active() is None
