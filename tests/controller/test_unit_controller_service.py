from __future__ import annotations

import random
from pathlib import Path

import pytest

from libs.common.config import RuntimeConfig
from libs.contracts.models import AssetDefinition, ControllerTickRequest, ProfileSnapshot
from services.controller.domain import ControllerService
from tests.support.inmemory_repositories import (
    InMemoryAssetRepository,
    InMemoryRevealFeedbackRepository,
    InMemoryTechniqueTransitionRepository,
)


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
            default_settings={
                "selection_profile": {
                    "asset_group": "credential-store",
                    "covered_techniques": ["T1552.001"],
                    "telemetry_value": 0.8,
                }
            },
        ),
        AssetDefinition(
            asset_id="asset-explore",
            asset_name="Discovery Portal",
            exposure_type="internal",
            interaction_level="medium",
            covers_tactics=["Discovery"],
            dependencies=[],
            default_settings={
                "selection_profile": {
                    "asset_group": "portal",
                    "covered_techniques": ["T1046"],
                    "telemetry_value": 0.6,
                }
            },
        ),
    ]


def test_tick_prefers_exploit_then_secondary_explore() -> None:
    service = ControllerService(
        InMemoryAssetRepository(_assets()),
        InMemoryTechniqueTransitionRepository(),
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
                conf_by_technique={"T1552.001": 0.9, "T1046": 0.2},
                recent_tactics=["Credential Access"],
                recent_techniques=["T1552.001"],
                recent_evidence_ids=["e-1"],
            ),
        )
    )

    assert [action.asset_id for action in response.actions] == [
        "asset-exploit",
        "asset-explore",
    ]
    assert response.decision_events[0].decision_type == "unlock"
    assert response.decision_events[0].details["selected_strategy"] == "exploit"
    assert response.decision_events[0].details["selected_technique"] == "T1552.001"
    assert response.decision_events[0].details["eligible_assets"] == [
        "asset-exploit",
        "asset-explore",
    ]


def test_tick_returns_noop_when_everything_is_already_unlocked() -> None:
    service = ControllerService(
        InMemoryAssetRepository(_assets()),
        InMemoryTechniqueTransitionRepository(),
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


def test_tick_uses_public_prior_to_boost_next_technique() -> None:
    service = ControllerService(
        InMemoryAssetRepository(_assets()),
        InMemoryTechniqueTransitionRepository({"T1552.001": {"T1046": 0.9}}),
        config=RuntimeConfig(epsilon=0.0),
        rng=random.Random(0),
    )

    response = service.tick(
        ControllerTickRequest(
            attacker_key="198.51.100.32",
            binding_id="binding-3",
            profile=ProfileSnapshot(
                attacker_key="198.51.100.32",
                conf_by_tactic={"Credential Access": 0.2, "Discovery": 0.0},
                conf_by_technique={"T1552.001": 0.1, "T1046": 0.1},
                recent_tactics=["Credential Access"],
                recent_techniques=["T1552.001"],
                recent_evidence_ids=["e-2"],
            ),
        )
    )

    assert response.actions[0].asset_id == "asset-explore"


def test_tick_can_chain_first_internal_unlock_into_file_gated_asset() -> None:
    # This models the intended dependency chain: the controller first opens the
    # generic internal portal, then immediately opens a more specific asset once
    # the public-site breadcrumb evidence is present.
    assets = [
        AssetDefinition(
            asset_id="internal-portal",
            asset_name="Internal Portal",
            exposure_type="internal",
            interaction_level="medium",
            covers_tactics=["Discovery"],
            dependencies=[],
            default_settings={
                "selection_profile": {
                    "asset_group": "portal",
                    "covered_techniques": ["T1046"],
                    "telemetry_value": 0.6,
                }
            },
        ),
        AssetDefinition(
            asset_id="finance-share",
            asset_name="Finance Share",
            exposure_type="internal",
            interaction_level="medium",
            covers_tactics=["Credential Access", "Collection"],
            dependencies=["internal-portal"],
            default_settings={
                "unlock_signals": {
                    "any_http_paths": ["/backup/db_backup_2024.sql.bak"],
                    "any_http_indicators": ["path:.bak"],
                },
                "selection_profile": {
                    "asset_group": "data-share",
                    "covered_techniques": ["T1005", "T1552.001"],
                    "telemetry_value": 0.85,
                },
            },
        ),
    ]
    service = ControllerService(
        InMemoryAssetRepository(assets),
        InMemoryTechniqueTransitionRepository(),
        config=RuntimeConfig(epsilon=0.0),
        rng=random.Random(0),
    )

    response = service.tick(
        ControllerTickRequest(
            attacker_key="198.51.100.40",
            binding_id="binding-4",
            profile=ProfileSnapshot(
                attacker_key="198.51.100.40",
                conf_by_tactic={"Credential Access": 0.9, "Discovery": 0.8},
                conf_by_technique={"T1552.001": 0.9, "T1046": 0.8},
                recent_tactics=["Credential Access", "Discovery"],
                recent_techniques=["T1552.001", "T1046"],
                recent_public_http_paths=["/backup/db_backup_2024.sql.bak"],
                recent_public_http_indicators=["path:.bak"],
                recent_evidence_ids=["e-3"],
            ),
        )
    )

    assert [action.asset_id for action in response.actions] == [
        "internal-portal",
        "finance-share",
    ]
    assert response.candidate_asset_ids == ["internal-portal", "finance-share"]


def test_tick_blocks_file_gated_asset_without_matching_public_http_signal() -> None:
    # Dependencies alone are not enough for file-gated assets. The matching
    # public HTTP path/rule/indicator must be present in the profile.
    assets = [
        AssetDefinition(
            asset_id="finance-share",
            asset_name="Finance Share",
            exposure_type="internal",
            interaction_level="medium",
            covers_tactics=["Credential Access", "Collection"],
            dependencies=["internal-portal"],
            default_settings={
                "unlock_signals": {
                    "any_http_paths": ["/backup/db_backup_2024.sql.bak"],
                    "any_http_indicators": ["path:.bak"],
                },
                "selection_profile": {
                    "asset_group": "data-share",
                    "covered_techniques": ["T1005", "T1552.001"],
                    "telemetry_value": 0.85,
                },
            },
        )
    ]
    service = ControllerService(
        InMemoryAssetRepository(assets),
        InMemoryTechniqueTransitionRepository(),
        config=RuntimeConfig(epsilon=0.0),
        rng=random.Random(0),
    )

    response = service.tick(
        ControllerTickRequest(
            attacker_key="198.51.100.41",
            binding_id="binding-5",
            profile=ProfileSnapshot(
                attacker_key="198.51.100.41",
                conf_by_tactic={"Credential Access": 0.9},
                conf_by_technique={"T1552.001": 0.9},
                recent_tactics=["Credential Access"],
                recent_techniques=["T1552.001"],
            ),
            unlocked_asset_ids=["internal-portal"],
        )
    )

    assert response.actions[0].action_type == "noop"
    assert response.candidate_asset_ids == []


def test_tick_can_use_internal_http_signal_for_later_asset() -> None:
    assets = [
        AssetDefinition(
            asset_id="backup-store",
            asset_name="Backup Store",
            exposure_type="internal",
            interaction_level="medium",
            covers_tactics=["Collection"],
            dependencies=["finance-share"],
            default_settings={
                "unlock_signals": {
                    "any_internal_http_paths": [
                        "/finance/archive/2024/payroll-archive.zip"
                    ],
                    "any_internal_http_indicators": ["path:.zip"],
                },
                "selection_profile": {
                    "asset_group": "backup",
                    "covered_techniques": ["T1005"],
                    "telemetry_value": 0.8,
                },
            },
        )
    ]
    service = ControllerService(
        InMemoryAssetRepository(assets),
        InMemoryTechniqueTransitionRepository(),
        config=RuntimeConfig(epsilon=0.0),
        rng=random.Random(0),
    )

    response = service.tick(
        ControllerTickRequest(
            attacker_key="198.51.100.42",
            binding_id="binding-6",
            profile=ProfileSnapshot(
                attacker_key="198.51.100.42",
                conf_by_tactic={"Collection": 0.8},
                conf_by_technique={"T1005": 0.8},
                recent_tactics=["Collection"],
                recent_techniques=["T1005"],
                recent_internal_http_paths=[
                    "/finance/archive/2024/payroll-archive.zip"
                ],
                recent_internal_http_indicators=["path:.zip"],
            ),
            unlocked_asset_ids=["finance-share"],
        )
    )

    assert [action.asset_id for action in response.actions] == ["backup-store"]


def test_tick_uses_feedback_coverage_gap_to_rank_explore_assets() -> None:
    assets = [
        AssetDefinition(
            asset_id="asset-exploit",
            asset_name="Credential Cache",
            exposure_type="internal",
            interaction_level="medium",
            covers_tactics=["Credential Access"],
            dependencies=[],
            default_settings={
                "selection_profile": {
                    "asset_group": "credential-store",
                    "covered_techniques": ["T1552.001"],
                    "telemetry_value": 0.8,
                }
            },
        ),
        AssetDefinition(
            asset_id="explore-low-gap",
            asset_name="Common Discovery",
            exposure_type="internal",
            interaction_level="medium",
            covers_tactics=["Discovery"],
            dependencies=[],
            default_settings={
                "selection_profile": {
                    "asset_group": "common-discovery",
                    "covered_techniques": ["T1046"],
                    "telemetry_value": 0.6,
                }
            },
        ),
        AssetDefinition(
            asset_id="explore-high-gap",
            asset_name="Under Sampled Discovery",
            exposure_type="internal",
            interaction_level="medium",
            covers_tactics=["Discovery"],
            dependencies=[],
            default_settings={
                "selection_profile": {
                    "asset_group": "under-sampled-discovery",
                    "covered_techniques": ["T1046"],
                    "telemetry_value": 0.6,
                }
            },
        ),
    ]
    service = ControllerService(
        InMemoryAssetRepository(assets),
        InMemoryTechniqueTransitionRepository(),
        config=RuntimeConfig(epsilon=0.0),
        rng=random.Random(0),
        feedback_repository=InMemoryRevealFeedbackRepository(
            {
                ("T1046", "common-discovery"): 0.0,
                ("T1046", "under-sampled-discovery"): 1.0,
            }
        ),
    )

    response = service.tick(
        ControllerTickRequest(
            attacker_key="198.51.100.44",
            binding_id="binding-8",
            profile=ProfileSnapshot(
                attacker_key="198.51.100.44",
                conf_by_technique={"T1552.001": 0.9, "T1046": 0.5},
                recent_techniques=["T1552.001", "T1046"],
                recent_evidence_ids=["e-8"],
            ),
        )
    )

    assert [action.asset_id for action in response.actions] == [
        "asset-exploit",
        "explore-high-gap",
    ]
    assert response.decision_events[1].details["coverage_gap"] == 1.0


def test_tick_skips_compose_asset_when_compose_file_is_missing(tmp_path: Path) -> None:
    missing_compose_file = tmp_path / "vendor" / "vulhub" / "docker-compose.yml"
    assets = [
        AssetDefinition(
            asset_id="log4shell-app",
            asset_name="Legacy Java App",
            exposure_type="internal",
            interaction_level="high",
            covers_tactics=["Initial Access"],
            dependencies=["internal-portal"],
            default_settings={
                "runtime": {
                    "backend": "compose",
                    "compose_file": str(missing_compose_file),
                },
                "unlock_signals": {
                    "any_http_rules": ["public_http_exploit_probe"],
                },
                "selection_profile": {
                    "asset_group": "vulnerable-web",
                    "covered_techniques": ["T1190"],
                    "telemetry_value": 1.0,
                },
            },
        )
    ]
    service = ControllerService(
        InMemoryAssetRepository(assets),
        InMemoryTechniqueTransitionRepository(),
        config=RuntimeConfig(epsilon=0.0),
        rng=random.Random(0),
    )

    response = service.tick(
        ControllerTickRequest(
            attacker_key="198.51.100.43",
            binding_id="binding-7",
            profile=ProfileSnapshot(
                attacker_key="198.51.100.43",
                conf_by_tactic={"Initial Access": 0.9},
                conf_by_technique={"T1190": 0.9},
                recent_tactics=["Initial Access"],
                recent_techniques=["T1190"],
                recent_public_http_rules=["public_http_exploit_probe"],
            ),
            unlocked_asset_ids=["internal-portal"],
        )
    )

    assert response.actions[0].action_type == "noop"
    assert response.candidate_asset_ids == []
