"""Default local wiring for the OpenCanary telemetry adapter."""

from __future__ import annotations

from libs.common.config import RuntimeConfig
from services.binding_service.runtime import get_runtime_service as get_binding_service
from services.opencanary.domain import OpenCanaryService
from services.opencanary.repository import FileOpenCanaryObservationRepository
from services.profiler.app import get_service as get_profiler_service

_config = RuntimeConfig()
_repository = FileOpenCanaryObservationRepository(
    f"{_config.state_dir}/opencanary_observations.json"
)
_service = OpenCanaryService(
    get_binding_service(),
    get_profiler_service(),
    _repository,
)


def get_runtime_repository() -> FileOpenCanaryObservationRepository:
    """Return the shared file-backed OpenCanary observation repository."""
    return _repository


def get_runtime_service() -> OpenCanaryService:
    """Return the shared OpenCanary service for local wiring."""
    return _service

