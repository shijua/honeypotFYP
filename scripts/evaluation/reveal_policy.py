#!/usr/bin/env python3
"""Replay scripted profiles against reveal-policy baselines.

The evaluator is deliberately offline: it does not start Docker or touch the
runtime route table. It answers the evaluation question "would this policy
reveal reasonable assets, hide implausible assets, or choose no_reveal for this
evidence sequence?" using the real catalog and controller scoring code.

Example scenario JSON:
    [{"scenario_id":"backup-probe","profile":{"conf_by_technique":{"T1552.001":0.9},"recent_techniques":["T1552.001"],"recent_evidence_ids":["e1"]},"expected_reasonable_assets":["finance-share"],"expected_hidden_assets":["web-admin-console"],"useful_followup_assets":["finance-share"]}]

Example command:
    python scripts/evaluation/reveal_policy.py tests/fixtures/reveal_policy_scenarios.json --policy all
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Literal

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from libs.common.config import RuntimeConfig
from libs.common.iterables import dedupe_preserve
from libs.contracts.models import AssetDefinition, ControllerTickRequest, ProfileSnapshot
from scripts.evaluation.charts import write_reveal_policy_chart
from services.controller.domain import ControllerService
from services.controller.repository import FileAssetRepository, FileAttackGroupTechniquePriorRepository

PolicyName = Literal[
    "passive",
    "all-open",
    "random-eligible",
    "gate-only",
    "top-recommendation",
    "controller",
]
ALL_POLICIES: tuple[PolicyName, ...] = (
    "passive",
    "all-open",
    "random-eligible",
    "gate-only",
    "top-recommendation",
    "controller",
)
TRACE_KEYS = {
    "selected_strategy",
    "selected_technique",
    "confidence_score",
    "recommendation_support",
    "technique_signal_score",
    "ordering",
    "eligible_assets",
    "rejected_assets",
    "prior_degraded",
}
NO_REVEAL_TRACE_KEYS = {
    "reveal_action",
    "no_reveal_reason",
    "prior_degraded",
    "rejected_assets",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate reveal policy choices on scripted offline scenarios.")
    parser.add_argument("scenario_file", type=Path, help="JSON array or JSONL scenarios with profiles or evidence_sequence records.")
    parser.add_argument("--catalog", type=Path, default=Path("data/assets/catalog.json"))
    parser.add_argument("--prior", type=Path, default=Path("data/technique_prior/attack_group_technique_prior.json"))
    parser.add_argument("--policy", choices=(*ALL_POLICIES, "all"), default="all")
    parser.add_argument("--output", type=Path, help="Optional JSON output path.")
    args = parser.parse_args()

    policies = ALL_POLICIES if args.policy == "all" else (args.policy,)
    report = evaluate_reveal_policies(
        scenario_file=args.scenario_file,
        catalog_path=args.catalog,
        prior_path=args.prior,
        policies=policies,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{text}\n", encoding="utf-8")
        write_reveal_policy_chart(report, args.output.with_suffix(".svg"))
    else:
        print(text)
    return 0 if report["ok"] else 1


def evaluate_reveal_policies(
    *,
    scenario_file: Path,
    catalog_path: Path,
    prior_path: Path,
    policies: tuple[PolicyName, ...] = ALL_POLICIES,
    config: RuntimeConfig | None = None,
) -> dict[str, Any]:
    """Return aggregate policy metrics for a JSONL scenario file.

    Example:
        evaluate_reveal_policies(... )["policies"]["controller"]["avg_opened_assets"] -> 1.5
    """
    scenarios = load_scenarios(scenario_file)
    assets = list(FileAssetRepository(catalog_path).list_all())
    base_config = config or RuntimeConfig()
    report = {
        "schema_version": "v1",
        "ok": bool(scenarios),
        "scenario_count": len(scenarios),
        "catalog": str(catalog_path),
        "prior": str(prior_path),
        "policies": {},
    }
    for policy in policies:
        rows = [
            evaluate_scenario(
                scenario,
                assets=assets,
                catalog_path=catalog_path,
                prior_path=prior_path,
                policy=policy,
                config=base_config,
            )
            for scenario in scenarios
        ]
        report["policies"][policy] = _aggregate_rows(rows)
    if "controller" in report["policies"]:
        controller = report["policies"]["controller"]
        report["ok"] = bool(scenarios) and (
            controller["hidden_violation_rate"] == 0
            and controller["irrelevant_reveal_rate"] == 0
            and controller["missing_expected_reveal_count"] == 0
            and controller["correct_no_reveal_rate"] == 1.0
        )
    return report


def load_scenarios(path: Path) -> list[dict[str, Any]]:
    """Read scenario fixtures from JSON object, JSON array, or JSONL.

    Example:
        {"scenarios": [{"scenario_id":"s1"}]} -> [{"scenario_id": "s1"}]
    """
    text = path.read_text(encoding="utf-8")
    stripped_text = text.strip()
    if stripped_text.startswith(("[", "{")):
        try:
            payload = json.loads(stripped_text)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            if isinstance(payload, dict):
                raw_scenarios = payload.get("scenarios")
                if raw_scenarios is None and payload.get("scenario_id"):
                    raw_scenarios = [payload]
            else:
                raw_scenarios = payload
            if not isinstance(raw_scenarios, list):
                raise ValueError(f"{path} must contain a JSON array or an object with a scenarios array")
            for index, item in enumerate(raw_scenarios, start=1):
                if not isinstance(item, dict):
                    raise ValueError(f"{path}:{index} must be a JSON object")
            return raw_scenarios

    scenarios: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        payload = json.loads(stripped)
        if not isinstance(payload, dict):
            raise ValueError(f"{path}:{line_number} must be a JSON object")
        scenarios.append(payload)
    return scenarios


def evaluate_scenario(
    scenario: dict[str, Any],
    *,
    assets: list[AssetDefinition],
    catalog_path: Path,
    prior_path: Path,
    policy: PolicyName,
    config: RuntimeConfig,
) -> dict[str, Any]:
    """Evaluate one scenario and return per-scenario reveal metrics.

    Example:
        all-open may reveal ["internal-portal", "finance-share"], while controller reveals ["finance-share"].
    """
    request = scenario_request(scenario)
    if policy == "all-open":
        opened_assets, decision_events = _all_open_reveals(assets, request)
        reveal_actions = _unlock_action_summaries(opened_assets)
    elif policy == "passive":
        opened_assets, decision_events = _passive_no_reveal(request)
        reveal_actions = []
    elif policy == "random-eligible":
        opened_assets, decision_events = _random_eligible_reveals(assets, request)
        reveal_actions = _unlock_action_summaries(opened_assets)
    elif policy == "gate-only":
        opened_assets, decision_events = _gate_only_reveals(assets, request)
        reveal_actions = _unlock_action_summaries(opened_assets)
    elif policy == "top-recommendation":
        opened_assets, decision_events = _top_recommendation_reveals(
            assets,
            request,
            prior_path=prior_path,
            config=config,
        )
        reveal_actions = _unlock_action_summaries(opened_assets)
    else:
        response = ControllerService(
            FileAssetRepository(catalog_path),
            FileAttackGroupTechniquePriorRepository(prior_path),
            config=config,
        ).tick(request)
        opened_assets = _controller_opened_assets(response.actions)
        reveal_actions = _controller_reveal_actions(response.actions)
        decision_events = [event.model_dump(mode="json") for event in response.decision_events]

    reasonable = set(string_list(scenario.get("expected_reasonable_assets")))
    hidden = set(string_list(scenario.get("expected_hidden_assets")))
    useful = (
        set(string_list(scenario.get("useful_followup_assets")))
        if "useful_followup_assets" in scenario
        else reasonable
    )
    diagnostic = (
        set(string_list(scenario.get("diagnostic_followup_assets")))
        if "diagnostic_followup_assets" in scenario
        else useful
    )
    opened_set = set(opened_assets)
    reasonable_reveals = opened_set & reasonable
    irrelevant_reveals = opened_set - reasonable
    hidden_violations = opened_set & hidden
    useful_reveals = opened_set & useful
    diagnostic_or_useful_reveals = opened_set & (useful | diagnostic)
    expected_no_reveal = bool(scenario.get("expected_no_reveal"))
    missing_expected_reveals = _missing_expected_reveals(
        reveal_actions,
        _expected_reveals(scenario),
    )
    gate_opened, _gate_events = _gate_only_reveals(assets, request)
    prior_influenced = policy == "controller" and opened_assets != gate_opened
    return {
        "scenario_id": str(scenario.get("scenario_id") or scenario.get("case_id") or "scenario"),
        "policy": policy,
        "opened_assets": opened_assets,
        "reveal_actions": reveal_actions,
        "opened_asset_count": len(opened_assets),
        "unlock_reveal_count": sum(1 for action in reveal_actions if action["action_type"] == "unlock"),
        "configuration_reveal_count": sum(1 for action in reveal_actions if action["action_type"] == "configure"),
        "reasonable_reveals": sorted(reasonable_reveals),
        "irrelevant_reveals": sorted(irrelevant_reveals),
        "hidden_violations": sorted(hidden_violations),
        "useful_reveals": sorted(useful_reveals),
        "diagnostic_or_useful_reveals": sorted(diagnostic_or_useful_reveals),
        "missing_expected_reveals": missing_expected_reveals,
        "expected_no_reveal": expected_no_reveal,
        "correct_no_reveal": expected_no_reveal and not opened_assets,
        "prior_influenced": prior_influenced,
        "profile_to_reveal_latency_ticks": 1 if opened_assets else None,
        "decision_trace_complete": _decision_trace_complete(decision_events) if decision_events else policy == "all-open",
        "decision_events": decision_events,
    }


def scenario_request(scenario: dict[str, Any]) -> ControllerTickRequest:
    """Build a controller tick request from one replay scenario.

    Example:
        {"attacker_key":"198.51.100.9","profile":{"recent_techniques":["T1046"]}}
        -> ControllerTickRequest(attacker_key="198.51.100.9", ...).
    """
    attacker_key = str(scenario.get("attacker_key") or "198.51.100.200")
    binding_id = str(scenario.get("binding_id") or f"binding-{scenario.get('scenario_id', 'scenario')}")
    profile_payload = scenario.get("profile")
    if isinstance(profile_payload, dict):
        profile = ProfileSnapshot.model_validate({"attacker_key": attacker_key, **profile_payload})
    else:
        profile = profile_from_evidence_sequence(attacker_key, scenario.get("evidence_sequence"))
    return ControllerTickRequest(
        attacker_key=attacker_key,
        binding_id=binding_id,
        profile=profile,
        unlocked_asset_ids=string_list(scenario.get("initial_unlocked_assets")),
        revealed_configurations=_revealed_configurations(scenario.get("revealed_configurations")),
    )


def _controller_opened_assets(actions: list[Any]) -> list[str]:
    """Return attacker-visible assets from unlock and configure actions."""
    opened: list[str] = []
    for action in actions:
        action_type = getattr(action, "action_type", None)
        asset_id = getattr(action, "asset_id", None)
        target_asset_id = getattr(action, "target_asset_id", None)
        if action_type == "unlock" and isinstance(asset_id, str):
            opened.append(asset_id)
        if action_type == "configure":
            exposed_asset = target_asset_id or asset_id
            if isinstance(exposed_asset, str):
                opened.append(exposed_asset)
    return dedupe_preserve(opened)


def _controller_reveal_actions(actions: list[Any]) -> list[dict[str, str]]:
    """Return compact action summaries for unlock-vs-config evaluation.

    Example:
        configure malware-sink -> dionaea-capture records action_type,
        source asset, target asset, and configuration id.
    """
    summaries: list[dict[str, str]] = []
    for action in actions:
        action_type = getattr(action, "action_type", None)
        action_type_value = getattr(action_type, "value", action_type)
        if action_type_value not in {"unlock", "configure"}:
            continue
        asset_id = getattr(action, "asset_id", None)
        if not isinstance(asset_id, str):
            continue
        summary = {"action_type": str(action_type_value), "asset_id": asset_id}
        target_asset_id = getattr(action, "target_asset_id", None)
        configuration_id = getattr(action, "configuration_id", None)
        if isinstance(target_asset_id, str):
            summary["target_asset_id"] = target_asset_id
        if isinstance(configuration_id, str):
            summary["configuration_id"] = configuration_id
        summaries.append(summary)
    return summaries


def _unlock_action_summaries(asset_ids: list[str]) -> list[dict[str, str]]:
    return [{"action_type": "unlock", "asset_id": asset_id} for asset_id in asset_ids]


def _expected_reveals(scenario: dict[str, Any]) -> list[dict[str, str]]:
    reveals = scenario.get("expected_reveals")
    if not isinstance(reveals, list):
        return []
    return [
        {
            key: value
            for key, value in reveal.items()
            if key in {"action_type", "asset_id", "target_asset_id", "configuration_id"}
            and isinstance(value, str)
        }
        for reveal in reveals
        if isinstance(reveal, dict)
    ]


def _missing_expected_reveals(
    actual: list[dict[str, str]],
    expected: list[dict[str, str]],
) -> list[str]:
    missing = []
    for reveal in expected:
        if not any(all(action.get(key) == value for key, value in reveal.items()) for action in actual):
            missing.append(json.dumps(reveal, sort_keys=True))
    return missing


def _revealed_configurations(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}
    return {
        str(asset_id): string_list(config_ids)
        for asset_id, config_ids in value.items()
        if isinstance(asset_id, str)
    }


def profile_from_evidence_sequence(attacker_key: str, raw_events: object) -> ProfileSnapshot:
    """Build a minimal ProfileSnapshot from replay evidence records.

    Example:
        [{"technique":"T1552.001","tactic":"Credential Access","public_http_path":"/.env"}]
        -> recent_techniques=["T1552.001"], recent_public_http_paths=["/.env"].
    """
    events = [item for item in raw_events if isinstance(item, dict)] if isinstance(raw_events, list) else []
    techniques = _values(events, "technique", "tech_id")
    tactics = _values(events, "tactic", "group")
    weights_by_technique = _max_weights(events, "technique", "tech_id")
    weights_by_tactic = _max_weights(events, "tactic", "group")
    return ProfileSnapshot(
        attacker_key=attacker_key,
        conf_by_technique=weights_by_technique,
        conf_by_tactic=weights_by_tactic,
        recent_techniques=dedupe_preserve(techniques),
        recent_tactics=dedupe_preserve(tactics),
        recent_evidence_ids=dedupe_preserve(_values(events, "evidence_id")),
        recent_public_http_paths=dedupe_preserve(_values(events, "public_http_path")),
        recent_public_http_rules=dedupe_preserve(_values(events, "public_http_rule")),
        recent_public_http_indicators=dedupe_preserve(_values(events, "public_http_indicator")),
        recent_internal_http_paths=dedupe_preserve(_values(events, "internal_http_path")),
        recent_internal_http_rules=dedupe_preserve(_values(events, "internal_http_rule")),
        recent_internal_http_indicators=dedupe_preserve(_values(events, "internal_http_indicator")),
        recent_asset_ids=dedupe_preserve(_values(events, "asset_id", "source_asset_id")),
    )


def _all_open_reveals(
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


def _passive_no_reveal(request: ControllerTickRequest) -> tuple[list[str], list[dict[str, Any]]]:
    """Return an explicit no_reveal baseline for scanner/boundary comparisons.

    Example:
        passive policy with any profile -> no opened assets.
    """
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


def _gate_only_reveals(
    assets: list[AssetDefinition],
    request: ControllerTickRequest,
    max_reveals: int = 2,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Reveal dependency-unblocked assets whose hard signals match the profile.

    Example:
        public_http_rule=public_http_exploit_probe opens assets declaring that rule.
    """
    opened = [
        asset.asset_id
        for asset in assets
        if _asset_dependency_ready(asset, request)
        and _asset_unlock_signals_match(asset, request)
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


def _random_eligible_reveals(
    assets: list[AssetDefinition],
    request: ControllerTickRequest,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Reveal one deterministic random eligible asset.

    Example:
        eligible=["finance-share", "web-admin-console"] -> one stable choice for baseline comparison.
    """
    eligible = [
        asset.asset_id
        for asset in assets
        if _asset_dependency_ready(asset, request)
        and _asset_unlock_signals_match(asset, request)
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


def _top_recommendation_reveals(
    assets: list[AssetDefinition],
    request: ControllerTickRequest,
    *,
    prior_path: Path,
    config: RuntimeConfig,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Reveal one eligible asset covering the highest supported recommended technique.

    Example:
        observed {"T1552.001"} + group prior recommends T1005 -> choose an eligible T1005 asset.
    """
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
            if _asset_dependency_ready(asset, request) and technique in _asset_covered_techniques(asset):
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


def _asset_dependency_ready(asset: AssetDefinition, request: ControllerTickRequest) -> bool:
    return (
        asset.exposure_type == "internal"
        and asset.asset_id not in request.unlocked_asset_ids
        and set(asset.dependencies).issubset(request.unlocked_asset_ids)
    )


def _asset_covered_techniques(asset: AssetDefinition) -> set[str]:
    selection_profile = asset.default_settings.get("selection_profile")
    if not isinstance(selection_profile, dict):
        return set()
    techniques = selection_profile.get("covered_techniques")
    return {item for item in techniques if isinstance(item, str)} if isinstance(techniques, list) else set()


def _asset_unlock_signals_match(asset: AssetDefinition, request: ControllerTickRequest) -> bool:
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


def _decision_trace_complete(decision_events: list[dict[str, Any]]) -> bool:
    for event in decision_events:
        details = event.get("details")
        if not isinstance(details, dict):
            continue
        if TRACE_KEYS.issubset(details):
            return True
        if NO_REVEAL_TRACE_KEYS.issubset(details):
            return True
    return False


def _aggregate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    opened = sum(int(row["opened_asset_count"]) for row in rows)
    unlock_reveals = sum(int(row["unlock_reveal_count"]) for row in rows)
    configuration_reveals = sum(int(row["configuration_reveal_count"]) for row in rows)
    reasonable = sum(len(row["reasonable_reveals"]) for row in rows)
    irrelevant = sum(len(row["irrelevant_reveals"]) for row in rows)
    hidden = sum(len(row["hidden_violations"]) for row in rows)
    useful = sum(len(row["useful_reveals"]) for row in rows)
    diagnostic_or_useful = sum(len(row["diagnostic_or_useful_reveals"]) for row in rows)
    missing_expected_reveals = sum(len(row["missing_expected_reveals"]) for row in rows)
    expected_no_reveal = sum(1 for row in rows if row["expected_no_reveal"])
    correct_no_reveal = sum(1 for row in rows if row["correct_no_reveal"])
    prior_influenced = sum(1 for row in rows if row["prior_influenced"])
    latencies = [
        float(row["profile_to_reveal_latency_ticks"])
        for row in rows
        if row["profile_to_reveal_latency_ticks"] is not None
    ]
    return {
        "scenario_count": len(rows),
        "opened_asset_count": opened,
        "unlock_reveal_count": unlock_reveals,
        "configuration_reveal_count": configuration_reveals,
        "avg_opened_assets": _ratio(opened, len(rows)),
        "reveal_correctness": _ratio(reasonable, opened),
        "irrelevant_reveal_rate": _ratio(irrelevant, opened),
        "hidden_violation_rate": _ratio(hidden, opened),
        "useful_evidence_per_reveal": _ratio(useful, opened),
        "diagnostic_or_useful_per_reveal": _ratio(diagnostic_or_useful, opened),
        "missing_expected_reveal_count": missing_expected_reveals,
        "expected_reveal_match_rate": _ratio(
            sum(1 for row in rows if not row["missing_expected_reveals"]),
            len(rows),
        ),
        "expected_no_reveal_count": expected_no_reveal,
        "correct_no_reveal_rate": _ratio(correct_no_reveal, expected_no_reveal),
        "prior_influence_rate": _ratio(prior_influenced, len(rows)),
        "decision_trace_completeness_rate": _ratio(
            sum(1 for row in rows if row["decision_trace_complete"]),
            len(rows),
        ),
        "profile_to_reveal_latency_ticks_avg": sum(latencies) / len(latencies) if latencies else None,
        "rows": rows,
    }


def _values(events: list[dict[str, Any]], *keys: str) -> list[str]:
    values: list[str] = []
    for event in events:
        for key in keys:
            value = event.get(key)
            if isinstance(value, str) and value:
                values.append(value)
                break
    return values


def _max_weights(events: list[dict[str, Any]], *keys: str) -> dict[str, float]:
    weights: dict[str, float] = {}
    for event in events:
        weight = event.get("weight", 0.8)
        score = float(weight) if isinstance(weight, (int, float)) else 0.8
        for value in _values([event], *keys):
            weights[value] = max(weights.get(value, 0.0), max(0.0, min(1.0, score)))
    return weights


def string_list(value: object) -> list[str]:
    """Return only non-empty string items from a JSON array-like value.

    Example:
        ["a", "", 1] -> ["a"]
    """
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
