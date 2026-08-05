from __future__ import annotations

from types import SimpleNamespace

from v2link_client.core.errors import ConfigBuildError
from v2link_client.ui.main_window import MainWindow


def _link(legacy_allow_insecure):
    return SimpleNamespace(
        security="tls",
        legacy_allow_insecure=legacy_allow_insecure,
        host="example.invalid",
        sni=None,
        display_name=lambda: "Synthetic profile",
    )


def test_legacy_true_warning_is_sanitized_and_false_is_silent() -> None:
    warning = MainWindow._validation_warning(None, _link(True))
    assert warning is not None
    assert "secure certificate verification" in warning
    assert "vless://" not in warning
    assert "11111111-1111-1111-1111-111111111111" not in warning
    assert "ab" * 32 not in warning
    assert MainWindow._validation_warning(None, _link(False)) is None
    assert MainWindow._validation_warning(None, _link(None)) is None


def test_profile_editor_success_can_carry_legacy_warning() -> None:
    link = _link(True)
    fake_window = SimpleNamespace(
        _validate_link=lambda _raw, persist_runtime_config: (link, None, None, 0, 0, 0),
        _validation_warning=lambda parsed: MainWindow._validation_warning(None, parsed),
        _profile_store=SimpleNamespace(find_by_url=lambda _raw: None),
    )
    ok, message = MainWindow._validate_link_for_dialog(fake_window, "synthetic")
    assert ok is True
    assert message.startswith("Valid: Synthetic profile")
    assert "Warning:" in message


def test_profile_editor_failure_remains_primary_and_clears_stale_success() -> None:
    cleared: list[str] = []
    profile = SimpleNamespace(id="synthetic-profile")

    def fail_validation(_raw, *, persist_runtime_config):
        assert persist_runtime_config is False
        raise ConfigBuildError(
            "synthetic validation failure",
            user_message="Xray rejected the configuration for a non-secret reason.",
        )

    fake_window = SimpleNamespace(
        _validate_link=fail_validation,
        _profile_store=SimpleNamespace(
            find_by_url=lambda _raw: profile,
            clear_profile_validation=lambda profile_id: cleared.append(profile_id),
        ),
    )

    ok, message = MainWindow._validate_link_for_dialog(fake_window, "synthetic")

    assert ok is False
    assert message == "Xray rejected the configuration for a non-secret reason."
    assert "Warning:" not in message
    assert cleared == ["synthetic-profile"]
