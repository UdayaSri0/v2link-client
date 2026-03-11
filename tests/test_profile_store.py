from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path

from v2link_client.core.profile_store import Profile, ProfileStore, connection_fingerprint


def test_profile_store_persists_profiles_and_default(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    store = ProfileStore(path=path)

    profile = Profile.create(name="Work", url="vless://example")
    saved = store.add_profile(profile)
    marked = store.mark_profile_validated(saved.id)
    assert marked is not None
    assert marked.validated is True
    assert marked.validation_fingerprint == connection_fingerprint(marked.url)
    store.set_default(saved.id)

    loaded = ProfileStore(path=path)
    loaded.load()

    assert len(loaded.profiles) == 1
    assert loaded.profiles[0].name == "Work"
    assert loaded.profiles[0].protocol == "vless"
    assert loaded.profiles[0].validated is True
    assert loaded.profiles[0].validated_at is not None
    assert loaded.profiles[0].validation_fingerprint == connection_fingerprint("vless://example")
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
