"""Repository adapters for sanitized high-interaction observations."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from libs.common.observation_repository import FileObservationRepository
from libs.contracts.models import HighInteractionObservation


class HighInteractionObservationRepository(Protocol):
    """Storage contract for Conpot/Dionaea/Honeytrap observations.

    Example:
        add(HighInteractionObservation(source="conpot", service="modbus", ...)) -> same observation
    """

    def add(self, observation: HighInteractionObservation) -> HighInteractionObservation:
        """Persist one sanitized observation."""
        ...

    def list_recent(self, limit: int = 100) -> Iterable[HighInteractionObservation]:
        """Return recent observations, newest last."""
        ...


class FileHighInteractionObservationRepository(
    FileObservationRepository[HighInteractionObservation]
):
    """File-backed high-interaction observation store.

    Example file shape:
        {"observations": [{"source": "dionaea", "event_type": "download.offer", ...}]}
    """

    def __init__(self, path: str | Path) -> None:
        super().__init__(path, HighInteractionObservation)
