from __future__ import annotations

from libs.common.config import RuntimeConfig
from services.gateway.domain import GatewayService
from services.gateway.repository import FileGatewayRouteRepository

_config = RuntimeConfig()
_repository = FileGatewayRouteRepository(f"{_config.state_dir}/gateway_routes.json")
_service = GatewayService(_repository)


def get_runtime_repository() -> FileGatewayRouteRepository:
    """Return the shared file-backed gateway repository for local wiring."""
    return _repository


def get_runtime_service() -> GatewayService:
    """Return the shared gateway service for local wiring."""
    return _service
