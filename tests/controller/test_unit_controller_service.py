from __future__ import annotations

import random

import pytest

from libs.common.config import RuntimeConfig
from libs.contracts.models import AssetDefinition, ControllerTickRequest, ProfileSnapshot
from services.controller.domain import ControllerService
from services.controller.repository import InMemoryAssetRepository, InMemoryTransitionRepository


pytestmark = pytest.mark.unit


def _assets() -> list[AssetDefinition]:
    return [
        AssetDefinition(
            asset_id="asset-exploit",
            asset_name="Credential Cache",
            exposure_type="internal",
            interaction_level="medium",
            covers_tactics=["Credential Access"],
            dependencies=[],
        ),
        AssetDefinition(
            asset_id="asset-explore",
            asset_name="Discovery Portal",
            exposure_type="internal",
            interaction_level="medium",
            covers_tactics=["Discovery"],
            dependencies=[],
        ),
    ]


def test_tick_prefers_exploit_then_secondary_explore() -> None:
    service = ControllerService(
        InMemoryAssetRepository(_assets()),
        InMemoryTransitionRepository(),
        config=RuntimeConfig(epsilon=0.0),
        rng=random.Random(0),
    )

    response = service.tick(
        ControllerTickRequest(
            attacker_key="198.51.100.30",
            binding_id="binding-1",
            profile=ProfileSnapshot(
                attacker_key="198.51.100.30",
                conf_by_tactic={"Credential Access": 0.9, "Discovery": 0.2},
                recent_tactics=["Credential Access"],
                recent_evidence_ids=["e-1"],
            ),
        )
    )

    assert [action.asset_id for action in response.actions] == [
        "asset-exploit",
        "asset-explore",
    ]
    assert response.decision_events[0].decision_type == "unlock"


def test_tick_returns_noop_when_everything_is_already_unlocked() -> None:
    service = ControllerService(
        InMemoryAssetRepository(_assets()),
        InMemoryTransitionRepository(),
        config=RuntimeConfig(epsilon=0.0, unlock_cap=2),
        rng=random.Random(0),
    )

    response = service.tick(
        ControllerTickRequest(
            attacker_key="198.51.100.31",
            binding_id="binding-2",
            profile=ProfileSnapshot(attacker_key="198.51.100.31"),
            unlocked_asset_ids=["asset-exploit", "asset-explore"],
        )
    )

    assert response.actions[0].action_type == "noop"
    assert response.decision_events[0].decision_type == "noop"


def test_tick_can_switch_to_explore_strategy() -> None:
    service = ControllerService(
        InMemoryAssetRepository(_assets()),
        InMemoryTransitionRepository(),
        config=RuntimeConfig(epsilon=1.0),
        rng=random.Random(0),
    )

    response = service.tick(
        ControllerTickRequest(
            attacker_key="198.51.100.32",
            binding_id="binding-3",
            profile=ProfileSnapshot(
                attacker_key="198.51.100.32",
                conf_by_tactic={"Credential Access": 0.2, "Discovery": 0.0},
                recent_tactics=["Credential Access"],
                recent_evidence_ids=["e-2"],
            ),
        )
    )

    assert response.actions[0].asset_id == "asset-explore"
