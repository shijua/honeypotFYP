"""Reusable file-backed store for append-only observation records."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Generic, TypeVar

from libs.common.json_store import JsonFileStore
from libs.contracts.models import VersionedModel


ObservationT = TypeVar("ObservationT", bound=VersionedModel)


class FileObservationRepository(Generic[ObservationT]):
    """Store typed observations under the shared `{"observations": [...]}` shape.

    Example:
        FileObservationRepository(path, CowrieObservation).add(observation)
        writes `observation.model_dump(mode="json")` to `path`.
    """

    def __init__(self, path: str | Path, model_type: type[ObservationT]) -> None:
        self._store = JsonFileStore(path, default_data={"observations": []})
        self._model_type = model_type

    def add(self, observation: ObservationT) -> ObservationT:
        self._store.append_to_list("observations", observation.model_dump(mode="json"))
        return observation

    def list_recent(self, limit: int = 100) -> Iterable[ObservationT]:
        payload = self._store.read()
        observations = payload.get("observations", [])[-limit:]
        return tuple(
            self._model_type.model_validate(item)
            for item in observations
        )
