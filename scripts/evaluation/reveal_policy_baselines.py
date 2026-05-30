"""Baseline reveal policies shared by offline reveal-policy evaluation."""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

from libs.common.config import RuntimeConfig
from libs.contracts.models import AssetDefinition, ControllerTickRequest
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
) -> tuple[list[str], list[dict[str, Any]]]:
    """Reveal dependency-unblocked assets whose hard signals match the profile."""
    opened = [
        asset.asset_id
        for asset in assets
        if asset_dependency_ready(asset, request)
        and asset_unlock_signals_match(asset, request)
    ][:max_reveals]
    return opened, [
        {
            "decision_type": "unlock" if opened else "noop",
            "details": {
                "selected_strategy": "gate-only",
                "eligible_assets": opened,
                "rejected_assets": {},
                "prior_degraded": None,
            },
        }
    ]


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
        if float(confidence) >= config.strong_technique_threshold
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
