"""Default local wiring for the Cowrie telemetry adapter.

The Cowrie adapter shares binding and profiler runtimes so SSH honeypot logs
enter the same MVP control loop as other telemetry.
"""

from __future__ import annotations

from libs.common.config import RuntimeConfig
from services.binding_service.runtime import get_runtime_service as get_binding_service
from services.cowrie.command_mapping import (
    CompositeCowrieCommandRuleCatalog,
    CowrieCommandRuleCatalog,
    FileCowrieCommandRuleCatalog,
)
from services.cowrie.domain import CowrieService
from services.cowrie.event_catalog import FileCowrieEventCatalog
from services.cowrie.repository import FileCowrieObservationRepository
from services.cowrie.sigma_mapping import SigmaCowrieCommandRuleCatalog
from services.profiler.app import get_service as get_profiler_service


def _command_catalog_for_config(config: RuntimeConfig) -> CowrieCommandRuleCatalog:
    """Build the selected Cowrie command catalog.

    `sigma` reads Sigma YAML at runtime. `hybrid` queries local rules first and
    then Sigma, deduping repeated rule IDs in the composite catalog.
    """
    mode = config.cowrie_command_mapping_mode.strip().lower()
    local_catalog = FileCowrieCommandRuleCatalog(config.cowrie_command_mapping_path)
    sigma_catalog = SigmaCowrieCommandRuleCatalog(config.cowrie_sigma_rules_path)
    if mode == "local":
        return local_catalog
    if mode == "sigma":
        return sigma_catalog
    if mode == "hybrid":
        return CompositeCowrieCommandRuleCatalog((local_catalog, sigma_catalog))
    raise ValueError("Cowrie command mapping mode must be 'local', 'sigma', or 'hybrid'")


_config = RuntimeConfig.from_env()
_repository = FileCowrieObservationRepository(
    f"{_config.state_dir}/cowrie_observations.json"
)
_event_catalog = FileCowrieEventCatalog(_config.cowrie_event_mapping_path)
_command_rule_catalog = _command_catalog_for_config(_config)
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
