"""Repository adapters for public entrypoint observations.

The entrypoint stores raw HTTP observations separately from profiler evidence
so researchers can inspect collection quality without overloading profiles.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from libs.common.json_store import JsonFileStore
from libs.contracts.models import EntrypointObservation


class EntrypointObservationRepository(Protocol):
    """Storage contract for low-interaction honeypot observations.

    Example:
        add(EntrypointObservation(path="/wp-login.php", ...)) -> same observation
    """

    def add(self, observation: EntrypointObservation) -> EntrypointObservation:
        """Persist one captured public entrypoint observation."""
        ...

    def list_recent(self, limit: int = 100) -> Iterable[EntrypointObservation]:
        """Return the most recent observations, newest last."""
        ...


class InMemoryEntrypointObservationRepository:
    """In-memory observation store used by tests and isolated local runs."""

    def __init__(self) -> None:
        self._observations: list[EntrypointObservation] = []

    def add(self, observation: EntrypointObservation) -> EntrypointObservation:
        self._observations.append(observation)
        return observation

    def list_recent(self, limit: int = 100) -> Iterable[EntrypointObservation]:
        return tuple(self._observations[-limit:])


class FileEntrypointObservationRepository:
    """File-backed observation store used by the default local runtime.

    Example file shape:
        {"observations": [{...EntrypointObservation...}]}
    """

    def __init__(self, path: str | Path) -> None:
        self._store = JsonFileStore(path, default_data={"observations": []})

    def add(self, observation: EntrypointObservation) -> EntrypointObservation:
        payload = self._store.read()
        payload.setdefault("observations", []).append(observation.model_dump(mode="json"))
        self._store.write(payload)
        return observation

    def list_recent(self, limit: int = 100) -> Iterable[EntrypointObservation]:
        payload = self._store.read()
        observations = payload.get("observations", [])[-limit:]
        return tuple(
            EntrypointObservation.model_validate(item)
            for item in observations
        )
