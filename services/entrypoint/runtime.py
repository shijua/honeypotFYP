"""Default local wiring for the public entrypoint service.

The entrypoint shares binding and profiler runtimes so captured traffic enters
the same MVP control loop used by the rest of the app.
"""

from __future__ import annotations

from libs.common.config import RuntimeConfig
from services.binding_service.runtime import get_runtime_service as get_binding_service
from services.entrypoint.domain import EntrypointService
from services.entrypoint.repository import FileEntrypointObservationRepository
from services.profiler.app import get_service as get_profiler_service

_config = RuntimeConfig()
_repository = FileEntrypointObservationRepository(
    f"{_config.state_dir}/entrypoint_observations.json"
)
_service = EntrypointService(
    get_binding_service(),
    get_profiler_service(),
    _repository,
)


def get_runtime_repository() -> FileEntrypointObservationRepository:
    """Return the shared file-backed entrypoint observation repository."""
    return _repository


def get_runtime_service() -> EntrypointService:
    """Return the shared entrypoint service for local wiring."""
    return _service
