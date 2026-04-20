"""FastAPI entrypoints for binding lifecycle operations.

This module exposes the HTTP surface for creating, refreshing, recycling,
and reading attacker-to-backend bindings.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException

from libs.contracts.models import (
    BindingRecord,
    HeartbeatRequest,
    RecycleRequest,
    ResolveBindingRequest,
)
from services.binding_service.domain import BindingNotFoundError, BindingService
from services.binding_service.runtime import get_runtime_service

app = FastAPI(title="binding_service", version="0.1.0")


def get_service() -> BindingService:
    """Return the default binding service used by the API.

    Example:
        The test suite can override this dependency with an isolated service.
    """
    # FastAPI dependency hook; tests replace this with a fake service.
    return get_runtime_service()


@app.post("/v1/bindings/resolve", response_model=BindingRecord)
def resolve_binding(
    request: ResolveBindingRequest,
    service: BindingService = Depends(get_service),
) -> BindingRecord:
    """Resolve a sticky binding for an attacker."""
    # Sticky bind: same attacker_key should resolve to the same active binding.
    return service.resolve(request)


@app.post("/v1/bindings/{binding_id}/heartbeat", response_model=BindingRecord)
def heartbeat(
    binding_id: str,
    request: HeartbeatRequest,
    service: BindingService = Depends(get_service),
) -> BindingRecord:
    """Refresh binding activity and TTL."""
    try:
        # Refresh activity timestamp and TTL for an active/recovered binding.
        return service.heartbeat(binding_id, request)
    except BindingNotFoundError as exc:
        raise HTTPException(status_code=404, detail="binding not found") from exc


@app.post("/v1/bindings/{binding_id}/recycle", response_model=BindingRecord)
def recycle(
    binding_id: str,
    request: RecycleRequest,
    service: BindingService = Depends(get_service),
) -> BindingRecord:
    """Recycle one binding with idle/hard mode."""
    try:
        # Mark binding recycled (idle or hard mode) for lifecycle cleanup.
        return service.recycle(binding_id, request)
    except BindingNotFoundError as exc:
        raise HTTPException(status_code=404, detail="binding not found") from exc


@app.get("/v1/bindings/{binding_id}", response_model=BindingRecord)
def get_binding(
    binding_id: str,
    service: BindingService = Depends(get_service),
) -> BindingRecord:
    """Read one binding by id."""
    try:
        return service.get(binding_id)
    except BindingNotFoundError as exc:
        raise HTTPException(status_code=404, detail="binding not found") from exc
