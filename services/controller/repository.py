"""Repository adapters for controller inputs.

This file provides two kinds of controller data:
- the asset catalog the controller may expose
- a small tactic transition table used for procedure-style scoring
"""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
from typing import Protocol

from libs.contracts.models import AssetDefinition


class AssetRepository(Protocol):
    """Storage contract for the controller asset catalog.

    Example:
        list_all() -> [AssetDefinition(asset_id="internal-portal", ...)]
    """

    def list_all(self) -> Iterable[AssetDefinition]:
        """Return the template catalog available to the controller."""
        ...


class TransitionRepository(Protocol):
    """Lookup contract for tactic-to-tactic transition support.

    Example:
        score_transition("Credential Access", "Collection") -> 0.9
    """

    def score_transition(self, current_tactic: str, candidate_tactic: str) -> float:
        """Return a light-weight transition score between ATT&CK tactics."""
        ...


class FileAssetRepository:
    """JSON-backed asset catalog used by the default controller runtime.

    Example file shape:
        [{
            "asset_id": "admin-jumpbox",
            "template_family": "ssh-honeypot",
            "protocols": ["ssh"],
            "ports": [22],
            "covers_tactics": ["Lateral Movement"],
            ...
        }]
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def list_all(self) -> Iterable[AssetDefinition]:
        with self._path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return tuple(AssetDefinition.model_validate(item) for item in payload)


class StaticTransitionRepository:
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
