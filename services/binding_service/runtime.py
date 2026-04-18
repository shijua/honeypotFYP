from __future__ import annotations

from libs.common.config import RuntimeConfig
from services.binding_service.domain import BindingService
from services.binding_service.repository import FileBindingRepository

_config = RuntimeConfig()
_repository = FileBindingRepository(f"{_config.state_dir}/bindings.json")
_service = BindingService(_repository, ttl_seconds=_config.binding_ttl_seconds)


def get_runtime_repository() -> FileBindingRepository:
    """Return the shared file-backed repository for default local wiring."""
    return _repository


def get_runtime_service() -> BindingService:
    """Return the shared binding service for default local wiring."""
    return _service
