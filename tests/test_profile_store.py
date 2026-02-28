from __future__ import annotations

import json
import os
from pathlib import Path

from v2link_client.core.profile_store import Profile, ProfileStore


def test_profile_store_persists_profiles_and_default(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    store = ProfileStore(path=path)

    profile = Profile.create(name="Work", url="vless://example")
    saved = store.add_profile(profile)
    store.set_default(saved.id)

    loaded = ProfileStore(path=path)
    loaded.load()

    assert len(loaded.profiles) == 1
    assert loaded.profiles[0].name == "Work"
    assert loaded.profiles[0].protocol == "vless"
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
