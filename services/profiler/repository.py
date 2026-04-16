from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

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
