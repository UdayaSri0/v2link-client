from __future__ import annotations

from datetime import datetime, timedelta, timezone

from v2link_client.core.latest_error import (
    LatestErrorStore,
    format_latest_error,
)


BASE_TIME = datetime(2026, 8, 5, 10, 0, 0, tzinfo=timezone.utc)


def test_error_is_sanitized_before_storage_and_formatting() -> None:
    store = LatestErrorStore()

    error = store.record(
        "Xray validation",
        "Profile validation failed for fixture.user@example.invalid",
        details=(
            "Xray rejected vless://01234567-89ab-cdef-0123-456789abcdef@"
            "example.invalid:443?token=fixture-token"
        ),
        timestamp=BASE_TIME,
        reason_code="invalid-response",
        context={"password": "standalone-fixture-pass", "HTTP status": 403},
    )

    assert error is not None
    retained = repr(error)
    copied = format_latest_error(error, application_version="0.2.4")
    for secret in (
        "fixture.user",
        "01234567-89ab",
        "fixture-token",
        "standalone-fixture-pass",
    ):
        assert secret not in retained
        assert secret not in copied
    assert "Xray validation" in copied
    assert "invalid-response" in copied
    assert "HTTP status: 403" in copied
    assert "Application version: v0.2.4" in copied
    assert "Sensitive values are redacted by default." in copied


def test_latest_active_uses_timestamp_and_source_specific_clear() -> None:
    store = LatestErrorStore()
    older = store.record(
        "system proxy",
        "Proxy apply failed",
        timestamp=BASE_TIME,
    )
    newer = store.record(
        "Xray startup",
        "Core startup failed",
        timestamp=BASE_TIME + timedelta(seconds=1),
    )

    assert store.latest_active() == newer
    assert store.clear("system proxy")
    assert store.latest_active() == newer
    assert store.clear("Xray startup")
    assert store.latest_active() is None
    assert older is not None


def test_rerecording_source_supersedes_stale_error() -> None:
    store = LatestErrorStore()
    store.record("profile validation", "First failure", timestamp=BASE_TIME)

    replacement = store.record(
        "profile validation",
        "Second failure",
        timestamp=BASE_TIME + timedelta(seconds=2),
    )

    assert store.latest_active() == replacement
    assert "First failure" not in store.format_latest()


def test_informational_warning_is_not_stored_as_latest_error() -> None:
    store = LatestErrorStore()

    result = store.record(
        "Xray validation",
        "Legacy compatibility warning",
        severity="informational",
        timestamp=BASE_TIME,
    )

    assert result is None
    assert store.latest_active() is None
    assert store.format_latest() == "No recent error is available to copy."


def test_unrelated_informational_event_does_not_clear_active_error() -> None:
    store = LatestErrorStore()
    active = store.record("traffic database", "Write failed", timestamp=BASE_TIME)

    store.record(
        "netmon/helper",
        "backend-not-implemented",
        severity="info",
        timestamp=BASE_TIME + timedelta(seconds=1),
    )

    assert store.latest_active() == active


def test_naive_timestamp_is_normalized_to_utc() -> None:
    store = LatestErrorStore()
    error = store.record(
        "application runtime",
        "Synthetic failure",
        timestamp=datetime(2026, 8, 5, 10, 0, 0),
    )

    assert error is not None
    assert error.timestamp.tzinfo == timezone.utc
    assert "2026-08-05T10:00:00+00:00" in store.format_latest()


def test_clear_all_removes_every_active_error() -> None:
    store = LatestErrorStore()
    store.record("one", "First", timestamp=BASE_TIME)
    store.record("two", "Second", timestamp=BASE_TIME)

    store.clear_all()

    assert store.latest_active() is None


def test_compound_and_camel_case_secret_context_keys_are_redacted() -> None:
    store = LatestErrorStore()

    error = store.record(
        "application runtime",
        "Synthetic failure",
        timestamp=BASE_TIME,
        context={
            "proxy_password": "SYNTH_CONTEXT_PASSWORD",
            "client_secret": "SYNTH_CONTEXT_SECRET",
            "accessToken": "SYNTH_CONTEXT_TOKEN",
            "HTTP status": 403,
        },
    )

    assert error is not None
    retained = repr(error)
    formatted = store.format_latest()
    for secret in (
        "SYNTH_CONTEXT_PASSWORD",
        "SYNTH_CONTEXT_SECRET",
        "SYNTH_CONTEXT_TOKEN",
    ):
        assert secret not in retained
        assert secret not in formatted
    assert "HTTP status: 403" in formatted


def test_unchanged_polled_error_does_not_displace_a_newer_error() -> None:
    store = LatestErrorStore()
    original_netmon = store.record(
        "Netmon helper",
        "Permission denied",
        details="Join the helper group.",
        reason_code="permission-denied",
        timestamp=BASE_TIME,
    )
    xray = store.record(
        "Xray startup",
        "Core startup failed",
        timestamp=BASE_TIME + timedelta(seconds=1),
    )

    repeated_netmon = store.record(
        "Netmon helper",
        "Permission denied",
        details="Join the helper group.",
        reason_code="permission-denied",
        timestamp=BASE_TIME + timedelta(seconds=2),
    )

    assert repeated_netmon is original_netmon
    assert store.latest_active() is xray


def test_retained_error_details_are_size_bounded() -> None:
    store = LatestErrorStore()

    error = store.record("application runtime", "Failure", details="λ" * 200_000)

    assert error is not None
    assert len(error.details.encode("utf-8")) <= 128 * 1024
    assert "[report truncated after 131072 bytes]" in error.details
