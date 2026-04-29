"""Default local wiring for the public entrypoint service."""

from __future__ import annotations

from libs.common.config import RuntimeConfig
from services.binding_service.runtime import get_runtime_service as get_binding_service
from services.entrypoint.domain import EntrypointService
from services.entrypoint.repository import FileEntrypointObservationRepository
from services.profiler.attack_catalog import MitreAttackCatalog
from services.profiler.domain import ProfilerService
from services.profiler.repository import FileEvidenceRepository, FileProfileRepository

_config = RuntimeConfig()
_repository = FileEntrypointObservationRepository(
    f"{_config.state_dir}/entrypoint_observations.json"
)
_profiler_service = ProfilerService(
    FileEvidenceRepository(f"{_config.state_dir}/evidence.json"),
    FileProfileRepository(f"{_config.state_dir}/profiles.json"),
    MitreAttackCatalog(_config.mitre_attack_stix_path),
    config=_config,
)
_service = EntrypointService(
    get_binding_service(),
    _repository,
    profiler_service=_profiler_service,
)


def get_runtime_repository() -> FileEntrypointObservationRepository:
    """Return the shared file-backed entrypoint observation repository."""
    return _repository


def get_runtime_service() -> EntrypointService:
    """Return the shared entrypoint service for local wiring."""
    return _service
