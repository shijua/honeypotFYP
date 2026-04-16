from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from libs.contracts.models import AssetDefinition


class AssetRepository(Protocol):
    def list_all(self) -> Iterable[AssetDefinition]:
        """Return the template catalog available to the controller."""
        ...


class TransitionRepository(Protocol):
    def score_transition(self, current_tactic: str, candidate_tactic: str) -> float:
        """Return a light-weight transition score between ATT&CK tactics."""
        ...


class InMemoryAssetRepository:
    """Static asset catalog used by the MVP controller."""

    def __init__(self, assets: list[AssetDefinition] | None = None) -> None:
        # Keep a small built-in catalog for the MVP.
        self._assets = assets or [
            AssetDefinition(
                asset_id="internal-portal",
                asset_name="Internal Portal",
                exposure_type="internal",
                interaction_level="medium",
                covers_tactics=["Discovery"],
                dependencies=[],
            ),
            AssetDefinition(
                asset_id="finance-share",
                asset_name="Finance File Share",
                exposure_type="internal",
                interaction_level="medium",
                covers_tactics=["Credential Access", "Collection"],
                dependencies=["internal-portal"],
            ),
            AssetDefinition(
                asset_id="git-internal",
                asset_name="Internal Git",
                exposure_type="internal",
                interaction_level="medium",
                covers_tactics=["Credential Access", "Discovery"],
                dependencies=["internal-portal"],
            ),
            AssetDefinition(
                asset_id="ops-db",
                asset_name="Operations Database",
                exposure_type="internal",
                interaction_level="medium",
                covers_tactics=["Credential Access", "Collection"],
                dependencies=["git-internal"],
            ),
            AssetDefinition(
                asset_id="admin-jumpbox",
                asset_name="Admin Jumpbox",
                exposure_type="internal",
                interaction_level="high",
                covers_tactics=["Lateral Movement", "Privilege Escalation"],
                dependencies=["git-internal"],
            ),
        ]

    def list_all(self) -> Iterable[AssetDefinition]:
        return tuple(self._assets)


class InMemoryTransitionRepository:
    """Small hand-written tactic transition table for MVP procedure scores."""

    def __init__(self) -> None:
        # Approximate likely next steps without a trained sequence model.
        self._transitions = {
            "Initial Access": {"Discovery": 0.8, "Execution": 0.5},
            "Execution": {"Credential Access": 0.7, "Discovery": 0.6},
            "Credential Access": {
                "Collection": 0.9,
                "Discovery": 0.7,
                "Lateral Movement": 0.6,
            },
            "Discovery": {
                "Credential Access": 0.7,
                "Collection": 0.4,
                "Lateral Movement": 0.6,
            },
            "Lateral Movement": {
                "Privilege Escalation": 0.7,
                "Collection": 0.8,
            },
        }

    def score_transition(self, current_tactic: str, candidate_tactic: str) -> float:
        # Missing edges mean "no support yet."
        return self._transitions.get(current_tactic, {}).get(candidate_tactic, 0.0)
