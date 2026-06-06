"""Baseline reveal policies shared by offline reveal-policy evaluation."""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

from libs.common.config import RuntimeConfig
from libs.contracts.models import ActionType, AssetDefinition, ControllerTickRequest
from services.controller.domain import ControllerService
from services.controller.repository import FileAttackGroupTechniquePriorRepository


def unlock_action_summaries(asset_ids: list[str]) -> list[dict[str, str]]:
    return [{"action_type": "unlock", "asset_id": asset_id} for asset_id in asset_ids]


def all_open_reveals(
    assets: list[AssetDefinition],
    request: ControllerTickRequest,
) -> tuple[list[str], list[dict[str, Any]]]:
    opened = [
        asset.asset_id
        for asset in assets
        if asset.exposure_type == "internal"
        and asset.asset_id not in request.unlocked_asset_ids
        and set(asset.dependencies).issubset(request.unlocked_asset_ids)
    ]
    return opened, [
        {
            "decision_type": "unlock",
            "details": {
                "selected_strategy": "all-open",
                "selected_technique": None,
                "eligible_assets": opened,
                "rejected_assets": {},
                "prior_degraded": None,
            },
        }
    ]


def passive_no_reveal(request: ControllerTickRequest) -> tuple[list[str], list[dict[str, Any]]]:
    """Return an explicit no_reveal baseline for scanner/boundary comparisons."""
    return [], [
        {
            "decision_type": "noop",
            "attacker_key": request.attacker_key,
            "binding_id": request.binding_id,
            "details": {
                "selected_strategy": "passive",
                "reveal_action": "no_reveal",
                "no_reveal_reason": "passive baseline never opens assets",
                "prior_degraded": None,
            },
        }
    ]


def gate_only_reveals(
    assets: list[AssetDefinition],
    request: ControllerTickRequest,
    max_reveals: int = 2,
    *,
    config: RuntimeConfig | None = None,
) -> tuple[list[str], list[dict[str, str]], list[dict[str, Any]]]:
    """Run the controller policy with only the technique prior term removed.

    The hard gate, exploit/explore passes, expected-gain ordering, structural
    priority, marker ordering, telemetry ordering, and tie-breaks all remain
    controller-owned. With prior support disabled, p_t is treated as a constant
    and expected gain becomes pure novelty: sum(1 - C_t).
    """
    response = ControllerService(
        _StaticAssetRepository(assets),
        _NoTechniquePriorRepository(),
        config=config,
        use_prior_support=False,
    ).tick(request)
    reveal_actions = [
        action
        for action in response.actions
        if action.action_type in {ActionType.unlock, ActionType.configure}
    ][:max_reveals]
    opened = [action.target_asset_id or action.asset_id for action in reveal_actions]
    action_summaries = []
    for action in reveal_actions:
        summary = {
            "action_type": action.action_type.value,
            "asset_id": action.asset_id,
        }
        if action.target_asset_id:
            summary["target_asset_id"] = action.target_asset_id
        if action.configuration_id:
            summary["configuration_id"] = action.configuration_id
        action_summaries.append(summary)
    events = [
        event.model_dump(mode="json")
        for event in response.decision_events
    ][:max_reveals]
    for event in events:
        details = event.get("details")
        if isinstance(details, dict):
            details["reveal_policy"] = "gate-only"
    return [asset_id for asset_id in opened if asset_id], action_summaries, events


class _StaticAssetRepository:
    """Minimal asset repository used by the offline prior ablation."""

    def __init__(self, assets: list[AssetDefinition]) -> None:
        self._assets = tuple(assets)

    def list_all(self) -> tuple[AssetDefinition, ...]:
        return self._assets


class _NoTechniquePriorRepository:
    """Prior repository placeholder that must not influence gate-only scoring."""

    @property
    def degraded_reason(self) -> None:
        return None

    def recommend(
        self,
        observed_techniques: set[str],
        *,
        top_k: int,
        support_threshold: float,
    ) -> dict[str, float]:
        return {}


def random_eligible_reveals(
    assets: list[AssetDefinition],
    request: ControllerTickRequest,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Reveal one deterministic random eligible asset."""
    eligible = [
        asset.asset_id
        for asset in assets
        if asset_dependency_ready(asset, request)
        and asset_unlock_signals_match(asset, request)
    ]
    opened = [random.Random(0).choice(eligible)] if eligible else []
    return opened, [
        {
            "decision_type": "unlock" if opened else "noop",
            "details": {
                "selected_strategy": "random-eligible",
                "eligible_assets": eligible,
                "rejected_assets": {},
                "prior_degraded": None,
            },
        }
    ]


def top_recommendation_reveals(
    assets: list[AssetDefinition],
    request: ControllerTickRequest,
    *,
    prior_path: Path,
    config: RuntimeConfig,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Reveal one eligible asset covering the highest supported recommended technique."""
    observed = {
        technique
        for technique, confidence in request.profile.conf_by_technique.items()
        if float(confidence) >= config.observed_technique_threshold
    }
    prior = FileAttackGroupTechniquePriorRepository(prior_path)
    recommendations = prior.recommend(
        observed,
        top_k=config.recommendation_top_k,
        support_threshold=config.recommendation_support_threshold,
    )
    for technique, support in sorted(recommendations.items(), key=lambda item: item[1], reverse=True):
        for asset in assets:
            if asset_dependency_ready(asset, request) and technique in asset_covered_techniques(asset):
                return [asset.asset_id], [
                    {
                        "decision_type": "unlock",
                        "details": {
                            "selected_strategy": "top-recommendation",
                            "selected_technique": technique,
                            "recommendation_support": round(support, 4),
                            "prior_degraded": prior.degraded_reason,
                        },
                    }
                ]
    return [], [
        {
            "decision_type": "noop",
            "details": {
                "selected_strategy": "top-recommendation",
                "reveal_action": "no_reveal",
                "prior_degraded": prior.degraded_reason,
            },
        }
    ]


def asset_dependency_ready(asset: AssetDefinition, request: ControllerTickRequest) -> bool:
    return (
        asset.exposure_type == "internal"
        and asset.asset_id not in request.unlocked_asset_ids
        and set(asset.dependencies).issubset(request.unlocked_asset_ids)
    )


def asset_covered_techniques(asset: AssetDefinition) -> set[str]:
    selection_profile = asset.default_settings.get("selection_profile")
    if not isinstance(selection_profile, dict):
        return set()
    techniques = selection_profile.get("covered_techniques")
    return {item for item in techniques if isinstance(item, str)} if isinstance(techniques, list) else set()


def asset_unlock_signals_match(asset: AssetDefinition, request: ControllerTickRequest) -> bool:
    unlock_signals = asset.default_settings.get("unlock_signals")
    if not isinstance(unlock_signals, dict) or not unlock_signals:
        return bool(request.profile.recent_evidence_ids or request.profile.recent_techniques)
    observed = {
        "any_http_paths": set(request.profile.recent_public_http_paths),
        "any_http_rules": set(request.profile.recent_public_http_rules),
        "any_http_indicators": set(request.profile.recent_public_http_indicators),
        "any_internal_http_paths": set(request.profile.recent_internal_http_paths),
        "any_internal_http_rules": set(request.profile.recent_internal_http_rules),
        "any_internal_http_indicators": set(request.profile.recent_internal_http_indicators),
        "any_techniques": set(request.profile.recent_techniques),
        "any_tactics": set(request.profile.recent_tactics),
    }
    for key, values in unlock_signals.items():
        required = {item for item in values if isinstance(item, str)} if isinstance(values, list) else set()
        if required and observed.get(key, set()).intersection(required):
            return True
    return False
