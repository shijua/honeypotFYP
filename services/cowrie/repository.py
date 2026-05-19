"""Repository adapters for sanitized Cowrie observations.

Cowrie observations are stored separately from profiler evidence so raw intake
quality can be inspected without changing controller-facing profiles.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from libs.common.observation_repository import FileObservationRepository
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


class FileCowrieObservationRepository(FileObservationRepository[CowrieObservation]):
    """File-backed Cowrie observation store used by the default local runtime.

    Example file shape:
        {"observations": [{...CowrieObservation...}]}
    """

    def __init__(self, path: str | Path) -> None:
        super().__init__(path, CowrieObservation)
