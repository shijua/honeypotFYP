"""Repository adapters for sanitized OpenCanary observations."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from libs.common.observation_repository import FileObservationRepository
from libs.contracts.models import OpenCanaryObservation


class OpenCanaryObservationRepository(Protocol):
    """Storage contract for sanitized OpenCanary observations."""

    def add(self, observation: OpenCanaryObservation) -> OpenCanaryObservation:
        """Persist one OpenCanary observation."""
        ...

    def list_recent(self, limit: int = 100) -> Iterable[OpenCanaryObservation]:
        """Return the most recent OpenCanary observations, newest last."""
        ...


class FileOpenCanaryObservationRepository(
    FileObservationRepository[OpenCanaryObservation]
):
    """File-backed OpenCanary observation store used by local runtime."""

    def __init__(self, path: str | Path) -> None:
        super().__init__(path, OpenCanaryObservation)
