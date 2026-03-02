from __future__ import annotations

from importlib import metadata

import v2link_client.version as version_mod


def _raise_not_found(_name: str) -> str:
    raise metadata.PackageNotFoundError


def test_get_semver_normalizes_installed_metadata(monkeypatch) -> None:
    monkeypatch.setattr(version_mod.metadata, "version", lambda _name: "v 0.1.9.0.0")
    version_mod.get_version.cache_clear()

    assert version_mod.get_semver() == "0.1.9.0.0"


def test_get_semver_falls_back_to_env_version(monkeypatch) -> None:
    monkeypatch.setattr(version_mod.metadata, "version", _raise_not_found)
    monkeypatch.setenv("V2LINK_CLIENT_VERSION", "v 1.2.3_Release")
    monkeypatch.setattr(version_mod, "_read_pyproject_version", lambda: None)
    version_mod.get_version.cache_clear()

    assert version_mod.get_semver() == "1.2.3"


def test_get_semver_defaults_when_no_source_available(monkeypatch) -> None:
    monkeypatch.setattr(version_mod.metadata, "version", _raise_not_found)
    monkeypatch.delenv("V2LINK_CLIENT_VERSION", raising=False)
    monkeypatch.delenv("VERSION", raising=False)
    monkeypatch.setattr(version_mod, "_read_pyproject_version", lambda: None)
    version_mod.get_version.cache_clear()

    assert version_mod.get_semver() == "0.0.0"
