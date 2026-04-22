"""Default local wiring for the Cowrie telemetry adapter.

The Cowrie adapter shares binding and profiler runtimes so SSH honeypot logs
enter the same MVP control loop as other telemetry.
"""

from __future__ import annotations

from libs.common.config import RuntimeConfig
from services.binding_service.runtime import get_runtime_service as get_binding_service
from services.cowrie.command_mapping import FileCowrieCommandRuleCatalog
from services.cowrie.domain import CowrieService
from services.cowrie.event_catalog import FileCowrieEventCatalog
from services.cowrie.repository import FileCowrieObservationRepository
from services.profiler.app import get_service as get_profiler_service

_config = RuntimeConfig()
_repository = FileCowrieObservationRepository(
    f"{_config.state_dir}/cowrie_observations.json"
)
_event_catalog = FileCowrieEventCatalog(_config.cowrie_event_mapping_path)
_command_rule_catalog = FileCowrieCommandRuleCatalog(
    _config.cowrie_command_mapping_path
)
_service = CowrieService(
    get_binding_service(),
    get_profiler_service(),
    _repository,
    _event_catalog,
    _command_rule_catalog,
)


def get_runtime_repository() -> FileCowrieObservationRepository:
    """Return the shared file-backed Cowrie observation repository."""
    return _repository


def get_runtime_service() -> CowrieService:
    """Return the shared Cowrie service for local wiring."""
    return _service
