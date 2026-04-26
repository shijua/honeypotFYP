"""Repository adapters for sanitized OpenCanary observations."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from libs.common.json_store import JsonFileStore
from libs.contracts.models import OpenCanaryObservation


class OpenCanaryObservationRepository(Protocol):
    """Storage contract for sanitized OpenCanary observations."""

    def add(self, observation: OpenCanaryObservation) -> OpenCanaryObservation:
        """Persist one OpenCanary observation."""
        ...

    def list_recent(self, limit: int = 100) -> Iterable[OpenCanaryObservation]:
        """Return the most recent OpenCanary observations, newest last."""
        ...


class InMemoryOpenCanaryObservationRepository:
    """In-memory OpenCanary observation store used by tests."""

    def __init__(self) -> None:
        self._observations: list[OpenCanaryObservation] = []

    def add(self, observation: OpenCanaryObservation) -> OpenCanaryObservation:
        self._observations.append(observation)
        return observation

    def list_recent(self, limit: int = 100) -> Iterable[OpenCanaryObservation]:
        return tuple(self._observations[-limit:])


class FileOpenCanaryObservationRepository:
    """File-backed OpenCanary observation store used by local runtime."""

    def __init__(self, path: str | Path) -> None:
        self._store = JsonFileStore(path, default_data={"observations": []})

    def add(self, observation: OpenCanaryObservation) -> OpenCanaryObservation:
        payload = self._store.read()
        payload.setdefault("observations", []).append(observation.model_dump(mode="json"))
        self._store.write(payload)
        return observation

    def list_recent(self, limit: int = 100) -> Iterable[OpenCanaryObservation]:
        payload = self._store.read()
        observations = payload.get("observations", [])[-limit:]
        return tuple(
            OpenCanaryObservation.model_validate(item)
            for item in observations
        )

