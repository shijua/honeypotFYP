from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException

from libs.contracts.models import (
    GatewayBindingState,
    GatewaySyncRequest,
    GatewaySyncResponse,
)
from services.gateway.domain import GatewayService, GatewayStateNotFoundError
from services.gateway.runtime import get_runtime_service

app = FastAPI(title="gateway", version="0.1.0")


def get_service() -> GatewayService:
    # Tests replace this dependency with an isolated service.
    return get_runtime_service()


@app.post("/v1/gateway/sync", response_model=GatewaySyncResponse)
def sync_binding(
    request: GatewaySyncRequest,
    service: GatewayService = Depends(get_service),
) -> GatewaySyncResponse:
    """Sync the latest binding exposure state into the gateway route table."""
    return service.sync(request)


@app.get("/v1/gateway/bindings/{binding_id}", response_model=GatewayBindingState)
def get_binding_state(
    binding_id: str,
    service: GatewayService = Depends(get_service),
) -> GatewayBindingState:
    """Return the gateway view for one binding."""
    try:
        return service.get_state(binding_id)
    except GatewayStateNotFoundError as exc:
        raise HTTPException(status_code=404, detail="gateway state not found") from exc
