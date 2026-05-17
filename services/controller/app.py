"""FastAPI entrypoint for controller ticks.

The controller API accepts an attacker profile plus the current binding view,
then returns the next actions the honeynet should apply.
"""

from __future__ import annotations

import random

from fastapi import Depends, FastAPI

from libs.common.config import RuntimeConfig
from libs.contracts.models import ControllerTickRequest, ControllerTickResponse
from services.controller.domain import ControllerService
from services.controller.repository import (
    FileAssetRepository,
    FileRevealFeedbackRepository,
    FileTechniqueTransitionRepository,
)

app = FastAPI(title="controller", version="0.1.0")

_config = RuntimeConfig.from_env()
_asset_repository = FileAssetRepository(_config.asset_catalog_path)
_transition_repository = FileTechniqueTransitionRepository(
    _config.attack_transition_prior_path,
    min_support=_config.transition_min_support,
    order2_min_support=_config.transition_order2_min_support,
    order3_min_support=_config.transition_order3_min_support,
)
_feedback_repository = FileRevealFeedbackRepository(_config.reveal_feedback_path)
_service = ControllerService(
    _asset_repository,
    _transition_repository,
    config=_config,
    # Seed RNG for deterministic local runs and tests.
    rng=random.Random(0),
    feedback_repository=_feedback_repository,
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
