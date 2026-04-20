"""Repository adapters for sanitized Cowrie observations.

Cowrie observations are stored separately from profiler evidence so raw intake
quality can be inspected without changing controller-facing profiles.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from libs.common.json_store import JsonFileStore
from libs.contracts.models import CowrieObservation


class CowrieObservationRepository(Protocol):
    """Storage contract for sanitized Cowrie observations.

    Example:
        add(CowrieObservation(eventid="cowrie.command.input", ...)) -> same observation
    """

    def add(self, observation: CowrieObservation) -> CowrieObservation:
        """Persist one Cowrie observation."""
        ...

    def list_recent(self, limit: int = 100) -> Iterable[CowrieObservation]:
        """Return the most recent Cowrie observations, newest last."""
        ...


class InMemoryCowrieObservationRepository:
    """In-memory Cowrie observation store used by tests and isolated runs."""

    def __init__(self) -> None:
        self._observations: list[CowrieObservation] = []

    def add(self, observation: CowrieObservation) -> CowrieObservation:
        self._observations.append(observation)
        return observation

    def list_recent(self, limit: int = 100) -> Iterable[CowrieObservation]:
        return tuple(self._observations[-limit:])


class FileCowrieObservationRepository:
    """File-backed Cowrie observation store used by the default local runtime.

    Example file shape:
        {"observations": [{...CowrieObservation...}]}
    """

    def __init__(self, path: str | Path) -> None:
        self._store = JsonFileStore(path, default_data={"observations": []})

    def add(self, observation: CowrieObservation) -> CowrieObservation:
        payload = self._store.read()
        payload.setdefault("observations", []).append(observation.model_dump(mode="json"))
        self._store.write(payload)
        return observation

    def list_recent(self, limit: int = 100) -> Iterable[CowrieObservation]:
        payload = self._store.read()
        observations = payload.get("observations", [])[-limit:]
        return tuple(
            CowrieObservation.model_validate(item)
            for item in observations
        )
