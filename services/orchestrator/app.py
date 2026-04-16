from __future__ import annotations

from fastapi import Depends, FastAPI

from libs.contracts.models import OrchestratorApplyRequest, OrchestratorApplyResponse
from services.binding_service.runtime import get_runtime_service
from services.orchestrator.domain import OrchestratorService
from services.orchestrator.repository import InMemoryRouteStateRepository

app = FastAPI(title="orchestrator", version="0.1.0")

_route_state_repository = InMemoryRouteStateRepository()
# Share binding runtime so apply-actions update the same in-memory state.
_service = OrchestratorService(get_runtime_service(), _route_state_repository)


def get_service() -> OrchestratorService:
    # Tests replace this dependency with an isolated service.
    return _service


@app.post("/v1/orchestration/apply", response_model=OrchestratorApplyResponse)
def apply_actions(
    request: OrchestratorApplyRequest,
    service: OrchestratorService = Depends(get_service),
) -> OrchestratorApplyResponse:
    """Apply controller actions against the current binding state."""
    return service.apply(request)
