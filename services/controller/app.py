"""FastAPI entrypoint for controller ticks.

The controller API accepts an attacker profile plus the current binding view,
then returns the next actions the honeynet should apply.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI

from libs.common.config import RuntimeConfig
from libs.contracts.models import ControllerTickRequest, ControllerTickResponse
from services.controller.domain import ControllerService
from services.controller.repository import (
    FileAttackHypothesisRepository,
    FileAttackGroupTechniquePriorRepository,
    FileAssetRepository,
)

app = FastAPI(title="controller", version="0.1.0")

_config = RuntimeConfig.from_env()
_asset_repository = FileAssetRepository(_config.asset_catalog_path)
_technique_prior_repository = FileAttackGroupTechniquePriorRepository(
    _config.attack_group_prior_path,
)
_hypothesis_repository = FileAttackHypothesisRepository(
    _config.attack_hypothesis_model_path,
)
_service = ControllerService(
    _asset_repository,
    _technique_prior_repository,
    hypothesis_repository=_hypothesis_repository,
    config=_config,
)


def get_service() -> ControllerService:
    """Return the default controller service used by the API."""
    # Tests replace this dependency with an isolated service.
    return _service


@app.post("/v1/controller/tick", response_model=ControllerTickResponse)
def controller_tick(
    request: ControllerTickRequest,
    service: ControllerService = Depends(get_service),
) -> ControllerTickResponse:
    """Rank plausible next assets and return controller actions."""
    return service.tick(request)
