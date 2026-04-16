from __future__ import annotations

from services.binding_service.domain import BindingService
from services.binding_service.repository import InMemoryBindingRepository

# Keep one shared in-memory binding state per process.
_repository = InMemoryBindingRepository()
_service = BindingService(_repository)


def get_runtime_repository() -> InMemoryBindingRepository:
    """Return the shared in-memory repository for default local wiring."""
    return _repository


def get_runtime_service() -> BindingService:
    """Return the shared binding service for default local wiring."""
    return _service
