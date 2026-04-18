from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from libs.common.json_store import JsonFileStore
from libs.contracts.models import ProfileSnapshot, TechniqueEvidence


class EvidenceRepository(Protocol):
    def add_many(
        self,
        attacker_key: str,
        evidences: list[TechniqueEvidence],
    ) -> list[TechniqueEvidence]:
        """Persist evidence records for one attacker."""
        ...

    def list_by_attacker(self, attacker_key: str) -> Iterable[TechniqueEvidence]:
        """Return all evidence records associated with attacker_key."""
        ...


class ProfileRepository(Protocol):
    def get(self, attacker_key: str) -> ProfileSnapshot | None:
        """Return the current snapshot for one attacker, if present."""
        ...

    def upsert(self, snapshot: ProfileSnapshot) -> ProfileSnapshot:
        """Insert or update one attacker profile snapshot."""
        ...


class InMemoryEvidenceRepository:
    """In-memory evidence store used by local runs and tests."""

    def __init__(self) -> None:
        # Keep evidence history by attacker_key.
        self._by_attacker: dict[str, list[TechniqueEvidence]] = {}

    def add_many(
        self,
        attacker_key: str,
        evidences: list[TechniqueEvidence],
    ) -> list[TechniqueEvidence]:
        bucket = self._by_attacker.setdefault(attacker_key, [])
        bucket.extend(evidences)
        return evidences

    def list_by_attacker(self, attacker_key: str) -> Iterable[TechniqueEvidence]:
        return tuple(self._by_attacker.get(attacker_key, ()))


class InMemoryProfileRepository:
    """In-memory snapshot store used by local runs and tests."""

    def __init__(self) -> None:
        # Keep the latest profile snapshot by attacker_key.
        self._by_attacker: dict[str, ProfileSnapshot] = {}

    def get(self, attacker_key: str) -> ProfileSnapshot | None:
        return self._by_attacker.get(attacker_key)

    def upsert(self, snapshot: ProfileSnapshot) -> ProfileSnapshot:
        self._by_attacker[snapshot.attacker_key] = snapshot
        return snapshot


class FileEvidenceRepository:
    """File-backed evidence store for the default local runtime."""

    def __init__(self, path: str | Path) -> None:
        self._store = JsonFileStore(path, default_data={"records": {}})

    def add_many(
        self,
        attacker_key: str,
        evidences: list[TechniqueEvidence],
    ) -> list[TechniqueEvidence]:
        payload = self._store.read()
        bucket = payload.setdefault("records", {}).setdefault(attacker_key, [])
        bucket.extend(evidence.model_dump(mode="json") for evidence in evidences)
        self._store.write(payload)
        return evidences

    def list_by_attacker(self, attacker_key: str) -> Iterable[TechniqueEvidence]:
        payload = self._store.read()
        return tuple(
            TechniqueEvidence.model_validate(item)
            for item in payload.get("records", {}).get(attacker_key, [])
        )


class FileProfileRepository:
    """File-backed profile store for the default local runtime."""

    def __init__(self, path: str | Path) -> None:
        self._store = JsonFileStore(path, default_data={"profiles": {}})

    def get(self, attacker_key: str) -> ProfileSnapshot | None:
        payload = self._store.read()
        item = payload.get("profiles", {}).get(attacker_key)
        if item is None:
            return None
        return ProfileSnapshot.model_validate(item)

    def upsert(self, snapshot: ProfileSnapshot) -> ProfileSnapshot:
        payload = self._store.read()
        payload.setdefault("profiles", {})[snapshot.attacker_key] = snapshot.model_dump(
            mode="json"
        )
        self._store.write(payload)
        return snapshot
