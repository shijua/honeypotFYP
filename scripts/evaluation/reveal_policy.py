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
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from libs.common.config import RuntimeConfig
from libs.common.iterables import dedupe_preserve
from libs.contracts.models import AssetDefinition, ControllerTickRequest, ProfileSnapshot
from scripts.evaluation.charts import write_hypothesis_posterior_chart, write_reveal_policy_chart
from services.controller.domain import ControllerService
from services.controller.repository import (
    FileAssetRepository,
    FileAttackGroupTechniquePriorRepository,
    FileAttackHypothesisRepository,
)

PolicyName = Literal[
    "passive",
    "all-open",
    "random-eligible",
    "gate-only",
    "top-recommendation",
    "controller",
    "hypothesis-testing",
]
ALL_POLICIES: tuple[PolicyName, ...] = (
    "passive",
    "all-open",
    "random-eligible",
    "gate-only",
    "top-recommendation",
    "controller",
    "hypothesis-testing",
)
TRACE_KEYS = {
    "selected_strategy",
    "reveal_role",
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
    parser.add_argument("--hypothesis-model", type=Path, default=Path("data/technique_prior/attack_hypothesis_model.json"))
    parser.add_argument("--policy", choices=(*ALL_POLICIES, "all"), default="all")
    parser.add_argument("--output", type=Path, help="Optional JSON output path.")
    args = parser.parse_args()

    policies = ALL_POLICIES if args.policy == "all" else (args.policy,)
    report = evaluate_reveal_policies(
        scenario_file=args.scenario_file,
        catalog_path=args.catalog,
        prior_path=args.prior,
        hypothesis_model_path=args.hypothesis_model,
        policies=policies,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{text}\n", encoding="utf-8")
        write_reveal_policy_chart(report, args.output.with_suffix(".svg"))
        write_hypothesis_posterior_chart(report, args.output.with_name(f"{args.output.stem}_posterior.svg"))
    else:
        print(text)
    return 0 if report["ok"] else 1


def evaluate_reveal_policies(
    *,
    scenario_file: Path,
    catalog_path: Path,
    prior_path: Path,
    hypothesis_model_path: Path | None = None,
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
    model_path = hypothesis_model_path or Path(base_config.attack_hypothesis_model_path)
    report = {
        "schema_version": "v1",
        "ok": bool(scenarios),
        "scenario_count": len(scenarios),
        "catalog": str(catalog_path),
        "prior": str(prior_path),
        "hypothesis_model": str(model_path),
        "policies": {},
    }
    for policy in policies:
        rows = [
            evaluate_scenario(
                scenario,
                assets=assets,
                catalog_path=catalog_path,
                prior_path=prior_path,
                hypothesis_model_path=model_path,
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
            and controller["unexpected_reveal_count"] == 0
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
    hypothesis_model_path: Path,
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
    elif policy == "hypothesis-testing":
        opened_assets, reveal_actions, decision_events = _hypothesis_testing_reveals(
            scenario,
            catalog_path=catalog_path,
            prior_path=prior_path,
            hypothesis_model_path=hypothesis_model_path,
            config=config,
        )
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
    expected_actions = _expected_reveals(scenario)
    allowed_actions = _allowed_reveals(scenario)
    action_constraints_declared = bool(expected_actions or allowed_actions)
    missing_expected_reveals = _missing_expected_reveals(reveal_actions, expected_actions)
    unexpected_reveal_actions = (
        _unexpected_reveal_actions(reveal_actions, [*expected_actions, *allowed_actions])
        if action_constraints_declared
        else []
    )
    gate_opened, _gate_events = _gate_only_reveals(assets, request)
    prior_influenced = policy == "controller" and opened_assets != gate_opened
    hypothesis_metrics = _hypothesis_metrics(
        scenario=scenario,
        policy=policy,
        decision_events=decision_events,
        reveal_actions=reveal_actions,
        hypothesis_model_path=hypothesis_model_path,
        convergence_threshold=config.hypothesis_convergence_threshold,
    )
    main_reveals, explore_reveals = _reveals_by_role(decision_events)
    touched_declared = isinstance(scenario.get("touched_assets"), list)
    touched_assets = string_list(scenario.get("touched_assets"))
    choice_signal = _choice_signal(
        policy=policy,
        main_reveals=main_reveals,
        explore_reveals=explore_reveals,
        touched_assets=touched_assets,
        touched_declared=touched_declared,
    )
    return {
        "scenario_id": str(scenario.get("scenario_id") or scenario.get("case_id") or "scenario"),
        "policy": policy,
        "opened_assets": opened_assets,
        "reveal_actions": reveal_actions,
        "main_reveal_assets": main_reveals,
        "explore_reveal_assets": explore_reveals,
        "touched_reveal_assets": sorted(set(touched_assets) & opened_set),
        "choice_signal": choice_signal,
        "opened_asset_count": len(opened_assets),
        "unlock_reveal_count": sum(1 for action in reveal_actions if action["action_type"] == "unlock"),
        "configuration_reveal_count": sum(1 for action in reveal_actions if action["action_type"] == "configure"),
        "reasonable_reveals": sorted(reasonable_reveals),
        "irrelevant_reveals": sorted(irrelevant_reveals),
        "hidden_violations": sorted(hidden_violations),
        "useful_reveals": sorted(useful_reveals),
        "diagnostic_or_useful_reveals": sorted(diagnostic_or_useful_reveals),
        "missing_expected_reveals": missing_expected_reveals,
        "unexpected_reveal_actions": unexpected_reveal_actions,
        "action_constraints_declared": action_constraints_declared,
        "expected_no_reveal": expected_no_reveal,
        "correct_no_reveal": expected_no_reveal and not opened_assets,
        "prior_influenced": prior_influenced,
        "profile_to_reveal_latency_ticks": 1 if opened_assets else None,
        "decision_trace_complete": _decision_trace_complete(decision_events) if decision_events else policy == "all-open",
        "decision_events": decision_events,
        **hypothesis_metrics,
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


def _reveals_by_role(decision_events: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Split controller reveal decisions into main and explore asset lists.

    Example:
        decision events with reveal_role main/explore -> (["git-internal"], ["malware-sink"]).
    """
    main: list[str] = []
    explore: list[str] = []
    for event in decision_events:
        details = event.get("details")
        if not isinstance(details, dict):
            continue
        asset_id = event.get("asset_added")
        role = details.get("reveal_role")
        if not isinstance(asset_id, str) or role not in {"main", "explore"}:
            continue
        if role == "main":
            main.append(asset_id)
        else:
            explore.append(asset_id)
    return dedupe_preserve(main), dedupe_preserve(explore)


def _choice_signal(
    *,
    policy: PolicyName,
    main_reveals: list[str],
    explore_reveals: list[str],
    touched_assets: list[str],
    touched_declared: bool,
) -> str | None:
    """Return the local preference signal implied by touched replay assets.

    Example:
        main=["git-internal"], explore=["malware-sink"], touched=["malware-sink"]
        -> "preferred_explore".
    """
    if policy != "controller" or not touched_declared or not main_reveals or not explore_reveals:
        return None
    touched = set(touched_assets)
    main_touched = bool(set(main_reveals) & touched)
    explore_touched = bool(set(explore_reveals) & touched)
    if main_touched and explore_touched:
        return "mixed"
    if main_touched:
        return "preferred_main"
    if explore_touched:
        return "preferred_explore"
    return "unresolved"


def _unlock_action_summaries(asset_ids: list[str]) -> list[dict[str, str]]:
    return [{"action_type": "unlock", "asset_id": asset_id} for asset_id in asset_ids]


def _expected_reveals(scenario: dict[str, Any]) -> list[dict[str, str]]:
    return _reveal_constraints(scenario.get("expected_reveals"))


def _allowed_reveals(scenario: dict[str, Any]) -> list[dict[str, str]]:
    return _reveal_constraints(scenario.get("allowed_reveals"))


def _reveal_constraints(raw_reveals: object) -> list[dict[str, str]]:
    if not isinstance(raw_reveals, list):
        return []
    return [
        {
            key: value
            for key, value in reveal.items()
            if key in {"action_type", "asset_id", "target_asset_id", "configuration_id"}
            and isinstance(value, str)
        }
        for reveal in raw_reveals
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


def _unexpected_reveal_actions(
    actual: list[dict[str, str]],
    allowed: list[dict[str, str]],
) -> list[str]:
    unexpected = []
    for action in actual:
        if not any(all(action.get(key) == value for key, value in constraint.items()) for constraint in allowed):
            unexpected.append(json.dumps(action, sort_keys=True))
    return unexpected


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


def _hypothesis_testing_reveals(
    scenario: dict[str, Any],
    *,
    catalog_path: Path,
    prior_path: Path,
    hypothesis_model_path: Path,
    config: RuntimeConfig,
) -> tuple[list[str], list[dict[str, str]], list[dict[str, Any]]]:
    """Replay a scenario as sequential diagnostic-test ticks.

    When a scenario supplies an evidence sequence, each prefix is treated as a
    decision point so the report can show posterior movement over time.
    """
    events = scenario.get("evidence_sequence")
    if isinstance(events, list) and events:
        prefixes = [events[: index + 1] for index in range(len(events))]
    else:
        prefixes = [None]

    unlocked_assets = string_list(scenario.get("initial_unlocked_assets"))
    revealed_configurations = _revealed_configurations(scenario.get("revealed_configurations"))
    opened_assets: list[str] = []
    reveal_actions: list[dict[str, str]] = []
    decision_events: list[dict[str, Any]] = []
    policy_config = replace(config, controller_policy_mode="hypothesis-testing")

    for step_index, prefix in enumerate(prefixes, start=1):
        tick_scenario = dict(scenario)
        tick_scenario["initial_unlocked_assets"] = list(unlocked_assets)
        tick_scenario["revealed_configurations"] = {
            asset_id: list(config_ids)
            for asset_id, config_ids in revealed_configurations.items()
        }
        if prefix is not None:
            tick_scenario.pop("profile", None)
            tick_scenario["evidence_sequence"] = prefix
        request = scenario_request(tick_scenario)
        response = ControllerService(
            FileAssetRepository(catalog_path),
            FileAttackGroupTechniquePriorRepository(prior_path),
            hypothesis_repository=FileAttackHypothesisRepository(hypothesis_model_path),
            config=policy_config,
        ).tick(request)
        step_events = [event.model_dump(mode="json") for event in response.decision_events]
        for event in step_events:
            details = event.get("details")
            if isinstance(details, dict):
                details["replay_step"] = step_index
        decision_events.extend(step_events)

        for action in response.actions:
            action_type = getattr(getattr(action, "action_type", None), "value", getattr(action, "action_type", None))
            asset_id = getattr(action, "asset_id", None)
            if action_type == "unlock" and isinstance(asset_id, str):
                unlocked_assets = dedupe_preserve([*unlocked_assets, asset_id])
            if action_type == "configure" and isinstance(asset_id, str):
                configuration_id = getattr(action, "configuration_id", None)
                if isinstance(configuration_id, str):
                    revealed_configurations.setdefault(asset_id, [])
                    revealed_configurations[asset_id] = dedupe_preserve(
                        [*revealed_configurations[asset_id], configuration_id]
                    )
                target_asset_id = getattr(action, "target_asset_id", None)
                if isinstance(target_asset_id, str):
                    unlocked_assets = dedupe_preserve([*unlocked_assets, target_asset_id])
        step_opened = _controller_opened_assets(response.actions)
        opened_assets = dedupe_preserve([*opened_assets, *step_opened])
        reveal_actions.extend(_controller_reveal_actions(response.actions))

    return opened_assets, reveal_actions, decision_events


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


def _hypothesis_metrics(
    *,
    scenario: dict[str, Any],
    policy: PolicyName,
    decision_events: list[dict[str, Any]],
    reveal_actions: list[dict[str, str]],
    hypothesis_model_path: Path,
    convergence_threshold: float,
) -> dict[str, Any]:
    """Return posterior/reveal diagnostic metrics for hypothesis-testing rows."""
    if policy != "hypothesis-testing":
        return {
            "posterior_trajectory": [],
            "reveals_to_convergence": None,
            "final_hypothesis_accuracy": None,
            "diagnostic_reveal_ratio": None,
            "unnecessary_reveal_count_after_convergence": None,
            "posterior_shift_per_reveal": None,
            "expected_hypothesis_id": None,
        }

    trajectory = _posterior_trajectory(decision_events)
    expected_hypothesis_id = _expected_hypothesis_id(scenario, hypothesis_model_path)
    final_hypothesis_id = trajectory[-1]["top_hypothesis_id"] if trajectory else None
    convergence_step = _convergence_step(trajectory, convergence_threshold)
    reveal_steps = [
        int(item["step"])
        for item in trajectory
        if isinstance(item.get("asset_added"), str)
    ]
    reveals_to_convergence = (
        sum(1 for step in reveal_steps if step <= convergence_step)
        if convergence_step is not None
        else None
    )
    unnecessary_reveals = (
        sum(1 for step in reveal_steps if step > convergence_step)
        if convergence_step is not None
        else 0
    )
    diagnostic_ratio, shift_per_reveal = _posterior_reveal_shift_metrics(trajectory)
    return {
        "posterior_trajectory": trajectory,
        "reveals_to_convergence": reveals_to_convergence,
        "final_hypothesis_accuracy": (
            final_hypothesis_id == expected_hypothesis_id
            if final_hypothesis_id and expected_hypothesis_id
            else None
        ),
        "diagnostic_reveal_ratio": diagnostic_ratio,
        "unnecessary_reveal_count_after_convergence": unnecessary_reveals,
        "posterior_shift_per_reveal": shift_per_reveal,
        "expected_hypothesis_id": expected_hypothesis_id,
        "reveal_action_count": len(reveal_actions),
    }


def _posterior_trajectory(decision_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract compact posterior points from controller decision events."""
    trajectory: list[dict[str, Any]] = []
    for fallback_step, event in enumerate(decision_events, start=1):
        details = event.get("details")
        if not isinstance(details, dict):
            continue
        posterior = details.get("hypothesis_posterior")
        if not isinstance(posterior, dict):
            continue
        clean_posterior = {
            str(hypothesis_id): round(float(probability), 6)
            for hypothesis_id, probability in posterior.items()
            if isinstance(probability, (int, float))
        }
        top_hypothesis_id = max(clean_posterior, key=clean_posterior.get, default=None)
        trajectory.append(
            {
                "step": int(details.get("replay_step") or fallback_step),
                "posterior": clean_posterior,
                "top_hypothesis_id": top_hypothesis_id,
                "max_posterior": round(max(clean_posterior.values(), default=0.0), 6),
                "top_hypotheses": details.get("top_hypotheses", []),
                "asset_added": event.get("asset_added"),
                "stop_reason": details.get("stop_reason"),
            }
        )
    return trajectory


def _expected_hypothesis_id(scenario: dict[str, Any], hypothesis_model_path: Path) -> str | None:
    """Choose the hypothesis that best matches expected or observed scenario techniques."""
    explicit = scenario.get("expected_hypothesis_id")
    if isinstance(explicit, str) and explicit:
        return explicit
    techniques = string_list(scenario.get("expected_hypothesis_techniques")) or _scenario_techniques(scenario)
    if not techniques:
        return None
    try:
        payload = json.loads(hypothesis_model_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    best_id: str | None = None
    best_score = -1.0
    for hypothesis in payload.get("hypotheses", []):
        if not isinstance(hypothesis, dict):
            continue
        hypothesis_id = hypothesis.get("hypothesis_id")
        likelihoods = hypothesis.get("likelihoods")
        if not isinstance(hypothesis_id, str) or not isinstance(likelihoods, dict):
            continue
        score = sum(float(likelihoods.get(technique, 0.0) or 0.0) for technique in techniques) / len(techniques)
        if score > best_score:
            best_id = hypothesis_id
            best_score = score
    return best_id


def _scenario_techniques(scenario: dict[str, Any]) -> list[str]:
    """Collect ATT&CK techniques from a scenario's expected and observed fields."""
    techniques: list[str] = []
    events = scenario.get("evidence_sequence")
    if isinstance(events, list):
        techniques.extend(_values([event for event in events if isinstance(event, dict)], "technique", "tech_id"))
    profile = scenario.get("profile")
    if isinstance(profile, dict):
        techniques.extend(string_list(profile.get("recent_techniques")))
        conf = profile.get("conf_by_technique")
        if isinstance(conf, dict):
            techniques.extend([key for key in conf if isinstance(key, str)])
    return dedupe_preserve(techniques)


def _convergence_step(trajectory: list[dict[str, Any]], threshold: float) -> int | None:
    """Return the first replay step where the posterior is considered converged."""
    for item in trajectory:
        if float(item.get("max_posterior", 0.0) or 0.0) >= threshold:
            return int(item["step"])
        if item.get("stop_reason") == "posterior_converged":
            return int(item["step"])
    return None


def _posterior_reveal_shift_metrics(trajectory: list[dict[str, Any]]) -> tuple[float | None, float | None]:
    """Measure whether reveal decisions occurred at posterior-changing steps."""
    reveal_shift_count = 0
    total_shift = 0.0
    reveal_count = 0
    previous: dict[str, float] | None = None
    previous_top: str | None = None
    for item in trajectory:
        posterior = item.get("posterior")
        if not isinstance(posterior, dict):
            continue
        clean = {str(key): float(value) for key, value in posterior.items() if isinstance(value, (int, float))}
        current_top = item.get("top_hypothesis_id") if isinstance(item.get("top_hypothesis_id"), str) else None
        if isinstance(item.get("asset_added"), str):
            reveal_count += 1
            shift = _posterior_distance(previous or clean, clean)
            total_shift += shift
            if shift >= 0.1 or (previous_top is not None and current_top != previous_top):
                reveal_shift_count += 1
        previous = clean
        previous_top = current_top
    if reveal_count == 0:
        return None, None
    return _ratio(reveal_shift_count, reveal_count), round(total_shift / reveal_count, 6)


def _posterior_distance(left: dict[str, float], right: dict[str, float]) -> float:
    """Return total-variation distance between two posterior distributions."""
    keys = set(left) | set(right)
    return 0.5 * sum(abs(float(left.get(key, 0.0)) - float(right.get(key, 0.0))) for key in keys)


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
    unexpected_reveals = sum(len(row["unexpected_reveal_actions"]) for row in rows)
    expected_no_reveal = sum(1 for row in rows if row["expected_no_reveal"])
    correct_no_reveal = sum(1 for row in rows if row["correct_no_reveal"])
    prior_influenced = sum(1 for row in rows if row["prior_influenced"])
    # Choice signals are only emitted when a controller row offered both main
    # and explore reveals and the fixture declared follow-up touched assets.
    choice_signals = [
        str(row["choice_signal"])
        for row in rows
        if isinstance(row.get("choice_signal"), str)
    ]
    resolved_choice_signals = [
        signal for signal in choice_signals if signal != "unresolved"
    ]
    choice_signal_counts = {
        signal: choice_signals.count(signal)
        for signal in ("preferred_main", "preferred_explore", "mixed", "unresolved")
    }
    latencies = [
        float(row["profile_to_reveal_latency_ticks"])
        for row in rows
        if row["profile_to_reveal_latency_ticks"] is not None
    ]
    reveals_to_convergence = [
        int(row["reveals_to_convergence"])
        for row in rows
        if isinstance(row.get("reveals_to_convergence"), int)
    ]
    final_hypothesis_accuracy = [
        bool(row["final_hypothesis_accuracy"])
        for row in rows
        if isinstance(row.get("final_hypothesis_accuracy"), bool)
    ]
    diagnostic_reveal_ratios = [
        float(row["diagnostic_reveal_ratio"])
        for row in rows
        if row.get("diagnostic_reveal_ratio") is not None
    ]
    posterior_shift_per_reveal = [
        float(row["posterior_shift_per_reveal"])
        for row in rows
        if row.get("posterior_shift_per_reveal") is not None
    ]
    unnecessary_after_convergence = sum(
        int(row["unnecessary_reveal_count_after_convergence"])
        for row in rows
        if isinstance(row.get("unnecessary_reveal_count_after_convergence"), int)
    )
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
        "unexpected_reveal_count": unexpected_reveals,
        "unexpected_reveal_action_rate": _ratio(unexpected_reveals, unlock_reveals + configuration_reveals),
        "expected_reveal_match_rate": _ratio(
            sum(1 for row in rows if not row["missing_expected_reveals"]),
            len(rows),
        ),
        "strict_expected_reveal_match_rate": _ratio(
            sum(
                1
                for row in rows
                if not row["missing_expected_reveals"] and not row["unexpected_reveal_actions"]
            ),
            len(rows),
        ),
        "expected_no_reveal_count": expected_no_reveal,
        "correct_no_reveal_rate": _ratio(correct_no_reveal, expected_no_reveal),
        "prior_influence_rate": _ratio(prior_influenced, len(rows)),
        "choice_signal_eligible_count": len(choice_signals),
        "choice_signal_count": len(resolved_choice_signals),
        "resolved_choice_rate": _ratio(len(resolved_choice_signals), len(choice_signals)),
        "choice_signal_counts": choice_signal_counts,
        "decision_trace_completeness_rate": _ratio(
            sum(1 for row in rows if row["decision_trace_complete"]),
            len(rows),
        ),
        "profile_to_reveal_latency_ticks_avg": sum(latencies) / len(latencies) if latencies else None,
        "reveals_to_convergence_avg": (
            round(sum(reveals_to_convergence) / len(reveals_to_convergence), 6)
            if reveals_to_convergence
            else None
        ),
        "final_hypothesis_accuracy_rate": _ratio(
            sum(1 for value in final_hypothesis_accuracy if value),
            len(final_hypothesis_accuracy),
        ),
        "diagnostic_reveal_ratio_avg": (
            round(sum(diagnostic_reveal_ratios) / len(diagnostic_reveal_ratios), 6)
            if diagnostic_reveal_ratios
            else None
        ),
        "unnecessary_reveal_count_after_convergence": unnecessary_after_convergence,
        "posterior_shift_per_reveal_avg": (
            round(sum(posterior_shift_per_reveal) / len(posterior_shift_per_reveal), 6)
            if posterior_shift_per_reveal
            else None
        ),
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
