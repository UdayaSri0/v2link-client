from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path

from v2link_client.core.profile_store import (
    Profile,
    ProfileStore,
    connection_fingerprint,
    validation_fingerprint,
    xray_binary_identity,
)
from v2link_client.core.xray_locator import XrayBinary


def test_profile_store_persists_profiles_and_default(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    store = ProfileStore(path=path)

    profile = Profile.create(name="Work", url="vless://example")
    saved = store.add_profile(profile)
    marked = store.mark_profile_validated(saved.id)
    assert marked is not None
    assert marked.validated is True
    assert marked.validation_fingerprint == validation_fingerprint(marked.url, "unavailable")
    store.set_default(saved.id)

    loaded = ProfileStore(path=path)
    loaded.load()

    assert len(loaded.profiles) == 1
    assert loaded.profiles[0].name == "Work"
    assert loaded.profiles[0].protocol == "vless"
    assert loaded.profiles[0].validated is True
    assert loaded.profiles[0].validated_at is not None
    assert loaded.profiles[0].validation_fingerprint == validation_fingerprint(
        "vless://example", "unavailable"
    )
    assert loaded.get_default() is not None
    assert loaded.get_default().id == saved.id


def test_profile_store_find_update_delete(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    store = ProfileStore(path=path)

    profile = store.add_profile(Profile.create(name="Home", url="trojan://abc"))
    found = store.find_by_url("trojan://abc")
    assert found is not None
    assert found.id == profile.id

    updated = store.update_profile(Profile(
        id=profile.id,
        name="Home Updated",
        url="ss://abc",
        protocol="unknown",
        created_at=profile.created_at,
        updated_at=profile.updated_at,
        last_used_at=profile.last_used_at,
        favorite=True,
        notes="note",
    ))
    assert updated.name == "Home Updated"
    assert updated.protocol == "ss"

    store.delete_profile(profile.id)
    assert store.find_by_url("ss://abc") is None


def test_profile_store_corrupted_json_is_backed_up(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    path.write_text("{ this is broken json", encoding="utf-8")

    store = ProfileStore(path=path)
    store.load()

    backup = tmp_path / "profiles.json.bak"
    assert backup.exists()
    assert not path.exists()
    assert store.profiles == []
    assert store.default_profile_id is None
    assert store.last_load_error is not None


def test_profile_store_atomic_write_creates_valid_json_and_permissions(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    store = ProfileStore(path=path)
    store.add_profile(Profile.create(name="Test", url="vless://x"))

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert isinstance(payload["profiles"], list)

    if os.name == "posix":
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600


def test_profile_store_loads_profiles_without_validation_fields(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    payload = {
        "schema_version": 1,
        "default_profile_id": "p1",
        "profiles": [
            {
                "id": "p1",
                "name": "Legacy",
                "url": "vless://example",
                "protocol": "vless",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "last_used_at": None,
                "favorite": False,
                "notes": "",
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")

    store = ProfileStore(path=path)
    store.load()

    assert len(store.profiles) == 1
    assert store.profiles[0].validated is False
    assert store.profiles[0].validated_at is None
    assert store.profiles[0].validation_fingerprint is None


def test_profile_validation_persists_for_metadata_only_changes(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    store = ProfileStore(path=path)
    base_url = (
        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
        "?encryption=none&security=tls&type=ws&host=cdn.example.com&path=%2Fws#Home"
    )
    saved = store.add_profile(Profile.create(name="Work", url=base_url))
    marked = store.mark_profile_validated(saved.id)
    assert marked is not None
    assert marked.validated is True

    renamed = store.update_profile(replace(marked, name="Work Renamed", notes="updated notes"))
    assert renamed.validated is True
    assert renamed.validation_fingerprint == marked.validation_fingerprint

    fragment_changed = store.update_profile(
        replace(
            renamed,
            url=base_url.replace("#Home", "#Office"),
        )
    )
    assert fragment_changed.validated is True
    assert fragment_changed.validation_fingerprint == marked.validation_fingerprint


def test_profile_validation_invalidates_when_connection_changes(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    store = ProfileStore(path=path)
    base_url = (
        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
        "?encryption=none&security=tls&type=ws&host=cdn.example.com&path=%2Fws#Home"
    )
    changed_url = (
        "vless://11111111-1111-1111-1111-111111111111@example.net:443"
        "?encryption=none&security=tls&type=ws&host=cdn.example.com&path=%2Fws#Home"
    )
    saved = store.add_profile(Profile.create(name="Work", url=base_url))
    marked = store.mark_profile_validated(saved.id)
    assert marked is not None
    assert marked.validated is True

    changed = store.update_profile(replace(marked, url=changed_url))
    assert changed.validated is False
    assert changed.validated_at is None
    assert changed.validation_fingerprint is None


def test_v023_connection_fingerprint_is_not_a_current_validation_identity(tmp_path: Path) -> None:
    profile = Profile.create(name="Legacy", url="vless://example")
    payload = profile.to_dict()
    payload.update(
        validated=True,
        validated_at="2026-01-01T00:00:00+00:00",
        validation_fingerprint=connection_fingerprint(profile.url),
    )
    restored = Profile.from_dict(payload, xray_identity="xray-a")
    assert restored is not None
    assert restored.url == profile.url
    assert restored.validated is False
    assert restored.validation_fingerprint is None


def test_validation_identity_depends_on_xray_identity() -> None:
    url = "vless://example"
    assert validation_fingerprint(url, "xray-a") == validation_fingerprint(url, "xray-a")
    assert validation_fingerprint(url, "xray-a") != validation_fingerprint(url, "xray-b")


def test_validation_identity_depends_on_schema_revision(monkeypatch) -> None:
    import v2link_client.core.profile_store as profile_store

    before = profile_store.validation_fingerprint("vless://example", "xray-a")
    monkeypatch.setattr(profile_store, "XRAY_CONFIG_SCHEMA_REVISION", 3)
    after = profile_store.validation_fingerprint("vless://example", "xray-a")
    assert before != after


def test_xray_binary_identity_covers_path_version_and_file_identity(tmp_path: Path) -> None:
    first_path = tmp_path / "xray-a"
    second_path = tmp_path / "xray-b"
    first_path.write_bytes(b"first")
    second_path.write_bytes(b"first")
    first = XrayBinary(str(first_path), "bundled", "v26.3.27", True)
    same = XrayBinary(str(first_path), "bundled", "v26.3.27", True)
    changed_version = XrayBinary(str(first_path), "bundled", "v26.4.1", True)
    changed_path = XrayBinary(str(second_path), "bundled", "v26.3.27", True)

    original_identity = xray_binary_identity(first)
    assert original_identity == xray_binary_identity(same)
    assert original_identity != xray_binary_identity(changed_version)
    assert original_identity != xray_binary_identity(changed_path)

    first_path.write_bytes(b"replacement binary")
    assert original_identity != xray_binary_identity(first)


def test_unavailable_xray_identity_is_deterministic() -> None:
    unavailable = XrayBinary(None, "bundled", None, False)
    assert xray_binary_identity(unavailable) == xray_binary_identity(unavailable)
