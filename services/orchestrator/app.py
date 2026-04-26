"""FastAPI entrypoint for applying controller actions.

The orchestrator API receives controller decisions, applies them to binding
state, and syncs the resulting exposure view into the gateway.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI

from libs.common.config import RuntimeConfig
from libs.contracts.models import OrchestratorApplyRequest, OrchestratorApplyResponse
from services.binding_service.runtime import get_runtime_service
from services.controller.repository import FileAssetRepository
from services.gateway.runtime import get_runtime_service as get_runtime_gateway_service
from services.orchestrator.domain import OrchestratorService
from services.orchestrator.template_runtime import (
    ComposeTemplateRuntime,
    DockerTemplateRuntime,
    FileTemplateRuntimeRepository,
    HybridTemplateRuntime,
    MockTemplateRuntime,
)

app = FastAPI(title="orchestrator", version="0.1.0")

# Share binding and gateway runtimes so apply-actions update the same state.
_config = RuntimeConfig()
_asset_repository = FileAssetRepository(_config.asset_catalog_path)
_template_runtime_repository = FileTemplateRuntimeRepository(
    f"{_config.state_dir}/asset_runtime.json"
)
_docker_template_runtime = DockerTemplateRuntime(_template_runtime_repository)
_compose_template_runtime = ComposeTemplateRuntime(_template_runtime_repository)
_mock_template_runtime = MockTemplateRuntime(_template_runtime_repository)
_template_runtime = HybridTemplateRuntime(
    _docker_template_runtime,
    _mock_template_runtime,
    _compose_template_runtime,
)
_service = OrchestratorService(
    get_runtime_service(),
    get_runtime_gateway_service(),
    _asset_repository,
    _template_runtime,
)


def get_service() -> OrchestratorService:
    """Return the default orchestrator service used by the API."""
    # Tests replace this dependency with an isolated service.
    return _service


@app.post("/v1/orchestration/apply", response_model=OrchestratorApplyResponse)
def apply_actions(
    request: OrchestratorApplyRequest,
    service: OrchestratorService = Depends(get_service),
) -> OrchestratorApplyResponse:
    """Apply controller actions against the current binding state."""
    return service.apply(request)
