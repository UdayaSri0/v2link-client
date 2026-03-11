"""Saved profile storage with XDG persistence and atomic writes."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any
from uuid import uuid4

from v2link_client.core.link_parser import parse_link
from v2link_client.core.storage import get_config_dir

PROFILES_SCHEMA_VERSION = 1
PROFILES_FILE = "profiles.json"
KNOWN_PROTOCOLS = {"vmess", "vless", "trojan", "ss"}
_URL_PREFIX_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://")


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def detect_protocol(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return "unknown"
    match = _URL_PREFIX_RE.match(raw)
    if not match:
        return "unknown"
    scheme = match.group(1).lower()
    if scheme in KNOWN_PROTOCOLS:
        return scheme
    return "unknown"


def basic_url_prefix_valid(url: str) -> bool:
    return bool(_URL_PREFIX_RE.match((url or "").strip()))


def connection_fingerprint(url: str) -> str | None:
    """Stable hash for connection-defining URL content."""
    raw = (url or "").strip()
    if not raw:
        return None
    try:
        link = parse_link(raw)
    except Exception:
        payload_data: dict[str, Any] = {"url": raw}
    else:
        payload_data = {
            "scheme": link.scheme,
            "user_id": link.user_id,
            "host": link.host,
            "port": int(link.port),
            "encryption": link.encryption,
            "security": link.security,
            "transport": link.transport,
            "sni": link.sni,
            "fingerprint": link.fingerprint,
            "allow_insecure": bool(link.allow_insecure),
            "header_type": link.header_type,
            "path": link.path,
            "ws_host": link.ws_host,
            "grpc_service_name": link.grpc_service_name,
            "flow": link.flow,
            "alpn": list(link.alpn) if link.alpn else [],
        }
    payload = json.dumps(
        payload_data,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Profile:
    id: str
    name: str
    url: str
    protocol: str
    created_at: str
    updated_at: str
    last_used_at: str | None
    favorite: bool = False
    notes: str = ""
    validated: bool = False
    validated_at: str | None = None
    validation_fingerprint: str | None = None

    @classmethod
    def create(
        cls,
        *,
        name: str,
        url: str,
        favorite: bool = False,
        notes: str = "",
        profile_id: str | None = None,
    ) -> "Profile":
        ts = _now_iso()
        cleaned_url = url.strip()
        return cls(
            id=profile_id or str(uuid4()),
            name=name.strip(),
            url=cleaned_url,
            protocol=detect_protocol(cleaned_url),
            created_at=ts,
            updated_at=ts,
            last_used_at=ts,
            favorite=bool(favorite),
            notes=notes.strip(),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Profile" | None:
        try:
            profile_id = str(data.get("id", "")).strip()
            name = str(data.get("name", "")).strip()
            url = str(data.get("url", "")).strip()
            created_at = str(data.get("created_at", "")).strip()
            updated_at = str(data.get("updated_at", "")).strip()
            last_used_raw = data.get("last_used_at")
            last_used_at = None if last_used_raw in {None, ""} else str(last_used_raw).strip()
            notes = str(data.get("notes", "")).strip()
            favorite = bool(data.get("favorite", False))
            protocol = str(data.get("protocol", "")).strip().lower() or detect_protocol(url)
            validated = bool(data.get("validated", False))
            validated_at_raw = data.get("validated_at")
            validated_at = (
                None if validated_at_raw in {None, ""} else str(validated_at_raw).strip()
            )
            validation_fingerprint_raw = data.get("validation_fingerprint")
            validation_fingerprint = (
                None
                if validation_fingerprint_raw in {None, ""}
                else str(validation_fingerprint_raw).strip()
            )
        except Exception:
            return None

        if not profile_id or not name or not url:
            return None

        if not created_at:
            created_at = _now_iso()
        if not updated_at:
            updated_at = created_at

        if protocol not in KNOWN_PROTOCOLS:
            protocol = "unknown"

        current_fingerprint = connection_fingerprint(url)
        if (
            not validated
            or not validation_fingerprint
            or not current_fingerprint
            or validation_fingerprint != current_fingerprint
        ):
            validated = False
            validated_at = None
            validation_fingerprint = None

        return cls(
            id=profile_id,
            name=name,
            url=url,
            protocol=protocol,
            created_at=created_at,
            updated_at=updated_at,
            last_used_at=last_used_at,
            favorite=favorite,
            notes=notes,
            validated=validated,
            validated_at=validated_at,
            validation_fingerprint=validation_fingerprint,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "protocol": self.protocol,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_used_at": self.last_used_at,
            "favorite": self.favorite,
            "notes": self.notes,
            "validated": self.validated,
            "validated_at": self.validated_at,
            "validation_fingerprint": self.validation_fingerprint,
        }


class ProfileStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (get_config_dir() / PROFILES_FILE)
        self.schema_version = PROFILES_SCHEMA_VERSION
        self.default_profile_id: str | None = None
        self.profiles: list[Profile] = []
        self.last_load_error: str | None = None

    def load(self) -> None:
        self.last_load_error = None
        if not self.path.exists():
            self.schema_version = PROFILES_SCHEMA_VERSION
            self.default_profile_id = None
            self.profiles = []
            return

        try:
            with self.path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except json.JSONDecodeError as exc:
            backup_path = self.path.with_suffix(".json.bak")
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if backup_path.exists():
                    backup_path.unlink()
                os.replace(self.path, backup_path)
                backup_note = f" Backed up as {backup_path.name}."
            except Exception:
                backup_note = " Failed to create backup file."
            self.schema_version = PROFILES_SCHEMA_VERSION
            self.default_profile_id = None
            self.profiles = []
            self.last_load_error = (
                f"Saved profiles file is corrupted ({exc})."
                f" Started with an empty profile list.{backup_note}"
            )
            return

        if not isinstance(payload, dict):
            self.schema_version = PROFILES_SCHEMA_VERSION
            self.default_profile_id = None
            self.profiles = []
            self.last_load_error = "Saved profiles file format is invalid. Started with an empty profile list."
            return

        schema_version = payload.get("schema_version", PROFILES_SCHEMA_VERSION)
        try:
            schema_int = int(schema_version)
        except (TypeError, ValueError):
            schema_int = PROFILES_SCHEMA_VERSION

        raw_default_id = payload.get("default_profile_id")
        default_profile_id = str(raw_default_id).strip() if isinstance(raw_default_id, str) else None

        parsed_profiles: list[Profile] = []
        raw_profiles = payload.get("profiles")
        if isinstance(raw_profiles, list):
            for item in raw_profiles:
                if not isinstance(item, dict):
                    continue
                parsed = Profile.from_dict(item)
                if parsed is not None:
                    parsed_profiles.append(parsed)

        ids = {profile.id for profile in parsed_profiles}
        if default_profile_id and default_profile_id not in ids:
            default_profile_id = None

        self.schema_version = schema_int
        self.default_profile_id = default_profile_id
        self.profiles = parsed_profiles

    def save(self) -> None:
        payload = {
            "schema_version": PROFILES_SCHEMA_VERSION,
            "default_profile_id": self.default_profile_id,
            "profiles": [profile.to_dict() for profile in self.profiles],
        }
        self._atomic_write_json(payload)

    def add_profile(self, profile: Profile) -> Profile:
        if self.get_by_id(profile.id) is not None:
            profile = replace(profile, id=str(uuid4()))
        self.profiles.append(profile)
        self.save()
        return profile

    def update_profile(self, profile: Profile) -> Profile:
        for idx, current in enumerate(self.profiles):
            if current.id == profile.id:
                cleaned_url = profile.url.strip()
                prior_fingerprint = connection_fingerprint(current.url)
                next_fingerprint = connection_fingerprint(cleaned_url)
                connection_changed = prior_fingerprint != next_fingerprint

                validated = (
                    current.validated
                    and current.validation_fingerprint is not None
                    and current.validation_fingerprint == next_fingerprint
                )
                validated_at = current.validated_at if validated else None
                validation_fingerprint = (
                    current.validation_fingerprint if validated else None
                )
                if connection_changed:
                    validated = False
                    validated_at = None
                    validation_fingerprint = None

                updated = replace(
                    profile,
                    name=profile.name.strip(),
                    url=cleaned_url,
                    notes=profile.notes.strip(),
                    protocol=detect_protocol(cleaned_url),
                    updated_at=_now_iso(),
                    validated=validated,
                    validated_at=validated_at,
                    validation_fingerprint=validation_fingerprint,
                )
                self.profiles[idx] = updated
                self.save()
                return updated
        raise KeyError(f"Profile not found: {profile.id}")

    def delete_profile(self, profile_id: str) -> None:
        self.profiles = [p for p in self.profiles if p.id != profile_id]
        if self.default_profile_id == profile_id:
            self.default_profile_id = None
        self.save()

    def set_default(self, profile_id: str | None) -> None:
        if profile_id is None:
            self.default_profile_id = None
            self.save()
            return
        if self.get_by_id(profile_id) is None:
            raise KeyError(f"Profile not found: {profile_id}")
        self.default_profile_id = profile_id
        self.save()

    def get_default(self) -> Profile | None:
        if not self.default_profile_id:
            return None
        return self.get_by_id(self.default_profile_id)

    def get_by_id(self, profile_id: str) -> Profile | None:
        for profile in self.profiles:
            if profile.id == profile_id:
                return profile
        return None

    def find_by_url(self, url: str) -> Profile | None:
        target = (url or "").strip()
        if not target:
            return None
        for profile in self.profiles:
            if profile.url.strip() == target:
                return profile
        return None

    def touch_last_used(self, profile_id: str) -> None:
        current = self.get_by_id(profile_id)
        if current is None:
            return
        updated = replace(current, last_used_at=_now_iso(), updated_at=_now_iso())
        self.update_profile(updated)

    def is_profile_validation_current(self, profile: Profile) -> bool:
        current_fingerprint = connection_fingerprint(profile.url)
        return bool(
            profile.validated
            and profile.validation_fingerprint
            and current_fingerprint
            and profile.validation_fingerprint == current_fingerprint
        )

    def mark_profile_validated(self, profile_id: str) -> Profile | None:
        current = self.get_by_id(profile_id)
        if current is None:
            return None

        fingerprint = connection_fingerprint(current.url)
        if not fingerprint:
            return None

        updated = replace(
            current,
            validated=True,
            validated_at=_now_iso(),
            validation_fingerprint=fingerprint,
            updated_at=_now_iso(),
        )
        for idx, existing in enumerate(self.profiles):
            if existing.id == profile_id:
                self.profiles[idx] = updated
                self.save()
                return updated
        return None

    def clear_profile_validation(self, profile_id: str) -> Profile | None:
        current = self.get_by_id(profile_id)
        if current is None:
            return None

        if not current.validated and not current.validated_at and not current.validation_fingerprint:
            return current

        updated = replace(
            current,
            validated=False,
            validated_at=None,
            validation_fingerprint=None,
            updated_at=_now_iso(),
        )
        for idx, existing in enumerate(self.profiles):
            if existing.id == profile_id:
                self.profiles[idx] = updated
                self.save()
                return updated
        return None

    def _atomic_write_json(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path_str = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=str(self.path.parent),
        )
        tmp_path = Path(tmp_path_str)
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self.path)
            if os.name == "posix":
                os.chmod(self.path, 0o600)
        except Exception:
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except Exception:
                pass
            raise
