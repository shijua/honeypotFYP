"""Default local wiring for the high-interaction telemetry adapter."""

from __future__ import annotations

from libs.common.config import RuntimeConfig
from services.binding_service.runtime import get_runtime_service as get_binding_service
from services.high_interaction.domain import HighInteractionService
from services.high_interaction.repository import FileHighInteractionObservationRepository
from services.profiler.app import get_service as get_profiler_service

_config = RuntimeConfig()
_repository = FileHighInteractionObservationRepository(
    f"{_config.state_dir}/high_interaction_observations.json"
)
_service = HighInteractionService(
    get_binding_service(),
    get_profiler_service(),
    _repository,
)


def get_runtime_repository() -> FileHighInteractionObservationRepository:
    """Return the shared file-backed high-interaction observation repository."""
    return _repository


def get_runtime_service() -> HighInteractionService:
    """Return the shared high-interaction service for local wiring."""
    return _service

