from __future__ import annotations

import random

from fastapi import Depends, FastAPI

from libs.contracts.models import ControllerTickRequest, ControllerTickResponse
from services.controller.domain import ControllerService
from services.controller.repository import InMemoryAssetRepository, InMemoryTransitionRepository

app = FastAPI(title="controller", version="0.1.0")

_asset_repository = InMemoryAssetRepository()
_transition_repository = InMemoryTransitionRepository()
_service = ControllerService(
    _asset_repository,
    _transition_repository,
    # Seed RNG for deterministic local runs and tests.
    rng=random.Random(0),
)


def get_service() -> ControllerService:
    # Tests replace this dependency with an isolated service.
    return _service


@app.post("/v1/controller/tick", response_model=ControllerTickResponse)
def controller_tick(
    request: ControllerTickRequest,
    service: ControllerService = Depends(get_service),
) -> ControllerTickResponse:
    """Rank plausible next assets and return controller actions."""
    return service.tick(request)
