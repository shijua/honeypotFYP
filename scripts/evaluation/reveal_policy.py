#!/usr/bin/env python3
"""Replay scripted profiles against reveal-policy baselines.

The evaluator is deliberately offline: it does not start Docker or touch the
runtime route table. It answers the evaluation question "would this policy
reveal scenario-supported assets, hide implausible assets, or choose no_reveal
for this evidence sequence?" using the real catalog and controller scoring code.

Example scenario JSON:
    [{"scenario_id":"backup-probe","profile":{"conf_by_technique":{"T1552.001":0.9},"recent_techniques":["T1552.001"],"recent_evidence_ids":["e1"]},"expected_reasonable_assets":["finance-share"],"expected_hidden_assets":["web-admin-console"],"useful_followup_assets":["finance-share"]}]

Example command:
    python scripts/evaluation/reveal_policy.py tests/fixtures/reveal_policy_scenarios.json --policy all
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Literal

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from libs.common.config import RuntimeConfig
from libs.common.iterables import dedupe_preserve
from libs.contracts.models import AssetDefinition, ControllerTickRequest, ProfileSnapshot
from scripts.evaluation.reveal_policy_baselines import (
    all_open_reveals,
    gate_only_reveals,
    passive_no_reveal,
    random_eligible_reveals,
    top_recommendation_reveals,
    unlock_action_summaries,
)
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
ReplayMode = Literal["snapshot", "sequence"]
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
    "reveal_role",
    "selected_technique",
    "confidence_score",
    "recommendation_support",
    "technique_signal_score",
    "ordering",
    "eligible_assets",
    "eligible_reveal_options",
    "eligible_configuration_variants",
    "rejected_assets",
    "prior_degraded",
    "prior_support_enabled",
}
NO_REVEAL_TRACE_KEYS = {
    "reveal_action",
    "no_reveal_reason",
    "prior_degraded",
    "prior_support_enabled",
    "rejected_assets",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate reveal policy choices on scripted offline scenarios.")
    parser.add_argument("scenario_file", type=Path, help="JSON array or JSONL scenarios with profiles or evidence_sequence records.")
    parser.add_argument("--catalog", type=Path, default=Path("data/assets/catalog.json"))
    parser.add_argument("--prior", type=Path, default=Path("data/technique_prior/attack_group_technique_prior.json"))
    parser.add_argument("--policy", choices=(*ALL_POLICIES, "all"), default="all")
    parser.add_argument(
        "--replay-mode",
        choices=("snapshot", "sequence"),
        default="snapshot",
        help="snapshot runs the historical one-tick replay; sequence replays timeline steps with cumulative state.",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON output path.")
    args = parser.parse_args()

    policies = ALL_POLICIES if args.policy == "all" else (args.policy,)
    report = evaluate_reveal_policies(
        scenario_file=args.scenario_file,
        catalog_path=args.catalog,
        prior_path=args.prior,
        policies=policies,
        replay_mode=args.replay_mode,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{text}\n", encoding="utf-8")
        write_reveal_policy_chart(report, args.output.with_suffix(".png"))
        print(format_reveal_policy_report_summary([(_scenario_set_label(args.scenario_file), report)]))
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
    replay_mode: ReplayMode = "snapshot",
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
        "replay_mode": replay_mode,
        "policies": {},
    }
    for policy in policies:
        rows = [
            (
                evaluate_timeline_scenario(
                    scenario,
                    assets=assets,
                    catalog_path=catalog_path,
                    prior_path=prior_path,
                    policy=policy,
                    config=base_config,
                )
                if replay_mode == "sequence"
                else evaluate_scenario(
                    scenario,
                    assets=assets,
                    catalog_path=catalog_path,
                    prior_path=prior_path,
                    policy=policy,
                    config=base_config,
                )
            )
            for scenario in scenarios
        ]
        report["policies"][policy] = _aggregate_rows(rows)
    if "controller" in report["policies"]:
        controller = report["policies"]["controller"]
        if replay_mode == "sequence":
            report["ok"] = bool(scenarios) and (
                controller["hidden_violation_rate"] == 0
                and controller["anchor_missing_expected_reveal_count"] == 0
                and controller["anchor_unexpected_reveal_count"] == 0
                and controller["anchor_failed_no_reveal_count"] == 0
                and controller["source_traceability_declared_rate"] == 1.0
            )
        else:
            report["ok"] = bool(scenarios) and (
                controller["hidden_violation_rate"] == 0
                and controller["irrelevant_reveal_rate"] == 0
                and controller["missing_expected_reveal_count"] == 0
                and controller["unexpected_reveal_count"] == 0
                and controller["correct_no_reveal_rate"] == 1.0
            )
    return report


def format_reveal_policy_report_summary(named_reports: list[tuple[str, dict[str, Any]]]) -> str:
    """Return Markdown tables for report metrics that are not plotted.

    The reveal-policy chart stays compact; these tables carry the supporting
    gate, rejection, and traceability numbers that belong in prose or a table.
    """
    rows = [
        (name, report.get("policies", {}).get("controller", {}))
        for name, report in named_reports
        if isinstance(report.get("policies", {}).get("controller", {}), dict)
    ]
    lines: list[str] = ["## Reveal policy report data", ""]
    lines.extend(
        [
            "### Scenario set summary",
            "| Scenario set | Scenarios | Decision steps | Anchor steps | Controller primary correctness | Unsupported reveal | Forbidden reveal | Correct no-reveal | Avg opened assets | Useful / reveal | Diagnostic-or-useful / reveal |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for name, controller in rows:
        lines.append(
            "| "
            f"{name} | "
            f"{int(controller.get('scenario_count', 0) or 0)} | "
            f"{int(controller.get('step_count', 0) or 0)} | "
            f"{int(controller.get('anchor_step_count', 0) or 0)} | "
            f"{_primary_correctness_cell(controller)} | "
            f"{_format_percent(controller.get('irrelevant_reveal_rate'))} | "
            f"{_format_percent(controller.get('hidden_violation_rate'))} | "
            f"{_format_percent(controller.get('correct_no_reveal_rate'))} | "
            f"{_format_float(controller.get('avg_opened_assets'))} | "
            f"{_format_percent(controller.get('useful_evidence_per_reveal'))} | "
            f"{_format_percent(controller.get('diagnostic_or_useful_per_reveal'))} |"
        )

    lines.extend(
        [
            "",
            "### Gate narrowing and candidate-space shape",
            "| Scenario set | Reveal decision space avg | Eligible reveal options avg | Option narrowing | 0 eligible options | 1 eligible option | 2+ eligible options |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for name, controller in rows:
        buckets = controller.get("gate_eligible_bucket_rates", {})
        buckets = buckets if isinstance(buckets, dict) else {}
        lines.append(
            "| "
            f"{name} | "
            f"{_format_float(controller.get('gate_reveal_decision_space_avg'))} | "
            f"{_format_float(controller.get('gate_eligible_reveal_options_avg'))} | "
            f"{_format_percent(controller.get('gate_narrowing_rate'))} | "
            f"{_format_percent(buckets.get('zero'))} | "
            f"{_format_percent(buckets.get('one'))} | "
            f"{_format_percent(buckets.get('two_plus'))} |"
        )

    lines.extend(
        [
            "",
            "### Prior influence",
            "| Scenario set | Prior changed step decision | Gate-only sufficient |",
            "|---|---:|---:|",
        ]
    )
    for name, controller in rows:
        influenced = int(controller.get("prior_influenced_step_count", 0) or 0)
        total = int(controller.get("prior_comparison_step_count", 0) or 0)
        lines.append(
            "| "
            f"{name} | "
            f"{_format_rate_count(influenced, total)} | "
            f"{_format_rate_count(max(total - influenced, 0), total)} |"
        )

    lines.extend(
        [
            "",
            "### Rejection reason distribution",
            "| Scenario set | Total rejections | Out of scope / no signal | Dependency not satisfied | Already revealed |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for name, controller in rows:
        counts = controller.get("rejection_reason_counts", {})
        counts = counts if isinstance(counts, dict) else {}
        total = sum(int(value or 0) for value in counts.values())
        lines.append(
            "| "
            f"{name} | "
            f"{total} | "
            f"{_format_rejection_cell(counts, 'out_of_scope_or_no_signal', total)} | "
            f"{_format_rejection_cell(counts, 'dependency_not_satisfied', total)} | "
            f"{_format_rejection_cell(counts, 'already_revealed', total)} |"
        )

    lines.extend(
        [
            "",
            "### Trace/audit checks",
            "| Scenario set | Decision trace completeness | Source traceability declared | Response-gate wait correctness |",
            "|---|---:|---:|---:|",
        ]
    )
    for name, controller in rows:
        expected = int(controller.get("response_gate_wait_expected_count", 0) or 0)
        correct = int(controller.get("response_gate_wait_correct_count", 0) or 0)
        response_gate = _format_rate_count(correct, expected) if expected else "n/a"
        lines.append(
            "| "
            f"{name} | "
            f"{_format_percent(controller.get('decision_trace_completeness_rate'))} | "
            f"{_format_percent(controller.get('source_traceability_declared_rate'))} | "
            f"{response_gate} |"
        )
    return "\n".join(lines)


def _scenario_set_label(path: Path) -> str:
    stem = path.stem
    if "main" in stem:
        return "Main multi-step scenarios"
    if "reveal_policy_scenarios" in stem or "regression" in stem:
        return "Regression edge-case scenarios"
    return stem.replace("_", " ").replace("-", " ").title()


def _primary_correctness_cell(controller: dict[str, Any]) -> str:
    anchors = int(controller.get("anchor_step_count", 0) or 0)
    if anchors:
        correct = int(controller.get("anchor_step_correct_count", 0) or 0)
        return _format_rate_count(correct, anchors)
    return _format_percent(controller.get("reveal_correctness"))


def _format_rejection_cell(counts: dict[str, Any], key: str, total: int) -> str:
    count = int(counts.get(key, 0) or 0)
    return f"{count} ({_format_percent(count / total if total else 0.0)})"


def _format_rate_count(numerator: int, denominator: int) -> str:
    return f"{_format_percent(numerator / denominator if denominator else 0.0)} ({numerator}/{denominator})"


def _format_percent(value: object) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    return f"{100 * number:.1f}%"


def _format_float(value: object) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    return f"{number:.2f}"


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
    opened_assets, reveal_actions, decision_events = _evaluate_policy_actions(
        policy=policy,
        assets=assets,
        request=request,
        catalog_path=catalog_path,
        prior_path=prior_path,
        config=config,
    )
    asset_sets = _scenario_asset_sets(scenario)
    reveal_constraints = _reveal_constraint_result(scenario, reveal_actions)
    opened_set = set(opened_assets)
    expected_no_reveal = bool(scenario.get("expected_no_reveal"))
    # Only the controller needs a same-state gate-only counterfactual to
    # attribute a changed choice to prior support. Re-running gate-only for
    # other baselines would not contribute to the prior-influence metric.
    if policy == "controller":
        gate_opened, gate_actions, _gate_events = gate_only_reveals(
            assets,
            request,
            config=config,
        )
        prior_comparable = _prior_is_healthy_for_comparison(decision_events)
        prior_influenced = prior_comparable and reveal_actions != gate_actions
        prior_comparison_step_count = 1 if prior_comparable else 0
    elif policy == "gate-only":
        gate_opened = list(opened_assets)
        prior_influenced = False
        prior_comparison_step_count = 0
    else:
        gate_opened = []
        prior_influenced = False
        prior_comparison_step_count = 0
    gate_metrics = _decision_gate_metrics(decision_events)
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
        "reasonable_reveals": sorted(opened_set & asset_sets["reasonable"]),
        "irrelevant_reveals": sorted(opened_set - asset_sets["reasonable"]),
        "hidden_violations": sorted(opened_set & asset_sets["hidden"]),
        "useful_reveals": sorted(opened_set & asset_sets["useful"]),
        "diagnostic_or_useful_reveals": sorted(opened_set & (asset_sets["useful"] | asset_sets["diagnostic"])),
        "missing_expected_reveals": reveal_constraints["missing_expected_reveals"],
        "unexpected_reveal_actions": reveal_constraints["unexpected_reveal_actions"],
        "action_constraints_declared": reveal_constraints["action_constraints_declared"],
        "expected_no_reveal": expected_no_reveal,
        "correct_no_reveal": expected_no_reveal and not opened_assets,
        "prior_influenced": prior_influenced,
        "prior_influenced_step_count": 1 if prior_influenced else 0,
        "prior_comparison_step_count": prior_comparison_step_count,
        "gate_only_opened_assets": gate_opened,
        "gate_decision_point_count": gate_metrics["decision_point_count"],
        "gate_eligible_reveal_option_total": gate_metrics["eligible_reveal_option_total"],
        "gate_reveal_decision_space_total": gate_metrics["reveal_decision_space_total"],
        "gate_narrowing_rate_total": gate_metrics["narrowing_rate_total"],
        "gate_reveal_decision_space_avg": gate_metrics["reveal_decision_space_avg"],
        "gate_eligible_reveal_options_avg": gate_metrics["eligible_reveal_options_avg"],
        "gate_narrowing_rate": gate_metrics["narrowing_rate"],
        "gate_eligible_bucket_counts": gate_metrics["eligible_bucket_counts"],
        "rejection_reason_counts": gate_metrics["rejection_reason_counts"],
        "profile_to_reveal_latency_ticks": 1 if opened_assets else None,
        "decision_trace_complete": _decision_trace_complete(decision_events) if decision_events else policy == "all-open",
        "decision_events": decision_events,
    }


def _evaluate_policy_actions(
    *,
    policy: PolicyName,
    assets: list[AssetDefinition],
    request: ControllerTickRequest,
    catalog_path: Path,
    prior_path: Path,
    config: RuntimeConfig,
) -> tuple[list[str], list[dict[str, str]], list[dict[str, Any]]]:
    """Return opened assets, compact reveal actions, and trace events for one policy."""
    if policy == "all-open":
        opened_assets, decision_events = all_open_reveals(assets, request)
        return opened_assets, unlock_action_summaries(opened_assets), decision_events
    if policy == "passive":
        opened_assets, decision_events = passive_no_reveal(request)
        return opened_assets, [], decision_events
    if policy == "random-eligible":
        opened_assets, decision_events = random_eligible_reveals(assets, request)
        return opened_assets, unlock_action_summaries(opened_assets), decision_events
    if policy == "gate-only":
        opened_assets, reveal_actions, decision_events = gate_only_reveals(
            assets,
            request,
            config=config,
        )
        return opened_assets, reveal_actions, decision_events
    if policy == "top-recommendation":
        opened_assets, decision_events = top_recommendation_reveals(
            assets,
            request,
            prior_path=prior_path,
            config=config,
        )
        return opened_assets, unlock_action_summaries(opened_assets), decision_events

    response = ControllerService(
        FileAssetRepository(catalog_path),
        FileAttackGroupTechniquePriorRepository(prior_path),
        config=config,
    ).tick(request)
    return (
        _controller_opened_assets(response.actions),
        _controller_reveal_actions(response.actions),
        [event.model_dump(mode="json") for event in response.decision_events],
    )


def _scenario_asset_sets(scenario: dict[str, Any]) -> dict[str, set[str]]:
    """Return the scenario asset classes used by all reveal quality metrics."""
    reasonable = set(string_list(scenario.get("expected_reasonable_assets")))
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
    return {
        "reasonable": reasonable,
        "hidden": set(string_list(scenario.get("expected_hidden_assets"))),
        "useful": useful,
        "diagnostic": diagnostic,
    }


def _reveal_constraint_result(
    scenario: dict[str, Any],
    reveal_actions: list[dict[str, str]],
) -> dict[str, Any]:
    """Compare actual reveal actions with exact expected/allowed constraints."""
    expected_actions = _reveal_constraints(scenario.get("expected_reveals"))
    allowed_actions = _reveal_constraints(scenario.get("allowed_reveals"))
    action_constraints_declared = bool(expected_actions or allowed_actions)
    return {
        "action_constraints_declared": action_constraints_declared,
        "missing_expected_reveals": _missing_expected_reveals(reveal_actions, expected_actions),
        "unexpected_reveal_actions": (
            _unexpected_reveal_actions(reveal_actions, [*expected_actions, *allowed_actions])
            if action_constraints_declared
            else []
        ),
    }


def evaluate_timeline_scenario(
    scenario: dict[str, Any],
    *,
    assets: list[AssetDefinition],
    catalog_path: Path,
    prior_path: Path,
    policy: PolicyName,
    config: RuntimeConfig,
) -> dict[str, Any]:
    """Replay one scenario step by step with cumulative profile and exposure state.

    A timeline replay models the reveal loop rather than a single aggregate
    snapshot: each step adds new evidence, the selected actions update the
    simulated unlocked/configured state, and later steps see that state.
    """
    timeline = scenario_timeline(scenario)
    cumulative_events: list[dict[str, Any]] = []
    unlocked_assets = string_list(scenario.get("initial_unlocked_assets"))
    revealed_configurations = _revealed_configurations(scenario.get("revealed_configurations"))
    step_rows: list[dict[str, Any]] = []

    for index, step in enumerate(timeline, start=1):
        step_events = _step_new_evidence(step)
        cumulative_events.extend(step_events)
        step_scenario = _scenario_for_timeline_step(
            scenario=scenario,
            step=step,
            cumulative_events=cumulative_events,
            unlocked_assets=unlocked_assets,
            revealed_configurations=revealed_configurations,
            index=index,
        )
        step_row = evaluate_scenario(
            step_scenario,
            assets=assets,
            catalog_path=catalog_path,
            prior_path=prior_path,
            policy=policy,
            config=config,
        )
        step_rows.append(step_row)
        unlocked_assets = dedupe_preserve([*unlocked_assets, *step_row["opened_assets"]])
        _record_revealed_configurations(revealed_configurations, step_row["reveal_actions"])

    final_row = _collapse_timeline_rows(scenario, policy, step_rows)
    final_row["timeline"] = step_rows
    final_row["source_traceability_status"] = _source_traceability_status(scenario, timeline)
    return final_row


def scenario_timeline(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    """Return explicit timeline steps, falling back to one snapshot step.

    Fixtures can migrate incrementally: old one-tick scenarios still replay as
    a single step, while full-process scenarios declare a `timeline` array.
    """
    raw_timeline = scenario.get("timeline")
    if isinstance(raw_timeline, list) and raw_timeline:
        return [step for step in raw_timeline if isinstance(step, dict)]
    return [
        {
            "step_id": "snapshot",
            "phase": "snapshot",
            "new_evidence": scenario.get("evidence_sequence", []),
            "profile": scenario.get("profile"),
            "expected_reveals": scenario.get("expected_reveals"),
            "allowed_reveals": scenario.get("allowed_reveals"),
            "expected_no_reveal": scenario.get("expected_no_reveal"),
            "touched_assets": scenario.get("touched_assets"),
            "expected_reason": scenario.get("expected_behavior"),
        }
    ]


def _scenario_for_timeline_step(
    *,
    scenario: dict[str, Any],
    step: dict[str, Any],
    cumulative_events: list[dict[str, Any]],
    unlocked_assets: list[str],
    revealed_configurations: dict[str, list[str]],
    index: int,
) -> dict[str, Any]:
    """Build a normal one-tick scenario for a timeline step."""
    step_id = str(step.get("step_id") or f"step-{index}")
    step_scenario: dict[str, Any] = {
        **scenario,
        "scenario_id": f"{scenario.get('scenario_id', 'scenario')}::{step_id}",
        "initial_unlocked_assets": unlocked_assets,
        "revealed_configurations": revealed_configurations,
        "evidence_sequence": cumulative_events,
        "expected_reveals": step.get("expected_reveals", []),
        "allowed_reveals": step.get("allowed_reveals", []),
        "expected_no_reveal": bool(step.get("expected_no_reveal")),
        "touched_assets": step.get("touched_assets", []),
    }
    if isinstance(step.get("profile"), dict):
        step_scenario["profile"] = step["profile"]
        step_scenario.pop("evidence_sequence", None)
    else:
        step_scenario.pop("profile", None)
    return step_scenario


def _step_new_evidence(step: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the evidence records introduced by one timeline step."""
    raw_evidence = step.get("new_evidence", [])
    if isinstance(raw_evidence, dict):
        return [raw_evidence]
    return [item for item in raw_evidence if isinstance(item, dict)] if isinstance(raw_evidence, list) else []


def _record_revealed_configurations(
    revealed_configurations: dict[str, list[str]],
    reveal_actions: list[dict[str, str]],
) -> None:
    """Track configured variants so later timeline steps do not reselect them."""
    for action in reveal_actions:
        if action.get("action_type") != "configure":
            continue
        asset_id = action.get("asset_id")
        configuration_id = action.get("configuration_id")
        if not asset_id or not configuration_id:
            continue
        revealed_configurations[asset_id] = dedupe_preserve(
            [*revealed_configurations.get(asset_id, []), configuration_id]
        )


def _collapse_timeline_rows(
    scenario: dict[str, Any],
    policy: PolicyName,
    step_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Aggregate step rows into the historical per-scenario row shape."""
    opened_assets = dedupe_preserve(
        asset_id for row in step_rows for asset_id in row["opened_assets"]
    )
    reveal_actions = _dedupe_reveal_actions(
        action for row in step_rows for action in row["reveal_actions"]
    )
    decision_events = [
        event for row in step_rows for event in row.get("decision_events", [])
    ]
    reveal_constraints = _reveal_constraint_result(scenario, reveal_actions)
    asset_sets = _scenario_asset_sets(scenario)
    opened_set = set(opened_assets)
    touched_assets = dedupe_preserve(
        [
            *string_list(scenario.get("touched_assets")),
            *[
                asset_id
                for step in scenario_timeline(scenario)
                for asset_id in string_list(step.get("touched_assets"))
            ],
            *[
                asset_id
                for row in step_rows
                for asset_id in row.get("touched_reveal_assets", [])
            ],
        ]
    )
    expected_no_reveal = bool(scenario.get("expected_no_reveal"))
    step_expected_no_reveal = sum(1 for row in step_rows if row["expected_no_reveal"])
    step_correct_no_reveal = sum(1 for row in step_rows if row["correct_no_reveal"])
    response_gate_expected = sum(
        1 for step in scenario_timeline(scenario) if step.get("expected_response_gate_wait")
    )
    response_gate_correct = sum(
        1
        for step, row in zip(scenario_timeline(scenario), step_rows)
        if step.get("expected_response_gate_wait") and not row["opened_assets"]
    )
    anchor_metrics = _anchor_metrics(scenario_timeline(scenario), step_rows)
    gate_metrics = _sum_gate_metrics(step_rows)
    return {
        "scenario_id": str(scenario.get("scenario_id") or scenario.get("case_id") or "scenario"),
        "policy": policy,
        "opened_assets": opened_assets,
        "reveal_actions": reveal_actions,
        "main_reveal_assets": dedupe_preserve(asset for row in step_rows for asset in row["main_reveal_assets"]),
        "explore_reveal_assets": dedupe_preserve(asset for row in step_rows for asset in row["explore_reveal_assets"]),
        "touched_reveal_assets": sorted(set(touched_assets) & opened_set),
        "choice_signal": None,
        "opened_asset_count": len(opened_assets),
        "unlock_reveal_count": sum(1 for action in reveal_actions if action["action_type"] == "unlock"),
        "configuration_reveal_count": sum(1 for action in reveal_actions if action["action_type"] == "configure"),
        "reasonable_reveals": sorted(opened_set & asset_sets["reasonable"]),
        "irrelevant_reveals": sorted(opened_set - asset_sets["reasonable"]),
        "hidden_violations": sorted(opened_set & asset_sets["hidden"]),
        "useful_reveals": sorted((opened_set & asset_sets["useful"]) or (set(touched_assets) & opened_set)),
        "diagnostic_or_useful_reveals": sorted(opened_set & (asset_sets["useful"] | asset_sets["diagnostic"])),
        "missing_expected_reveals": reveal_constraints["missing_expected_reveals"],
        "unexpected_reveal_actions": reveal_constraints["unexpected_reveal_actions"],
        "action_constraints_declared": reveal_constraints["action_constraints_declared"],
        "expected_no_reveal": expected_no_reveal,
        "correct_no_reveal": expected_no_reveal and not opened_assets,
        "prior_influenced": any(row["prior_influenced"] for row in step_rows),
        "prior_influenced_step_count": sum(1 for row in step_rows if row["prior_influenced"]),
        "prior_comparison_step_count": sum(
            int(row["prior_comparison_step_count"]) for row in step_rows
        ),
        "gate_only_opened_assets": dedupe_preserve(
            asset for row in step_rows for asset in row["gate_only_opened_assets"]
        ),
        "gate_decision_point_count": gate_metrics["decision_point_count"],
        "gate_eligible_reveal_option_total": gate_metrics["eligible_reveal_option_total"],
        "gate_reveal_decision_space_total": gate_metrics["reveal_decision_space_total"],
        "gate_narrowing_rate_total": gate_metrics["narrowing_rate_total"],
        "gate_reveal_decision_space_avg": gate_metrics["reveal_decision_space_avg"],
        "gate_eligible_reveal_options_avg": gate_metrics["eligible_reveal_options_avg"],
        "gate_narrowing_rate": gate_metrics["narrowing_rate"],
        "gate_eligible_bucket_counts": gate_metrics["eligible_bucket_counts"],
        "rejection_reason_counts": gate_metrics["rejection_reason_counts"],
        "profile_to_reveal_latency_ticks": _first_reveal_tick(step_rows),
        "decision_trace_complete": all(row["decision_trace_complete"] for row in step_rows),
        "decision_events": decision_events,
        "step_count": len(step_rows),
        "step_expected_no_reveal_count": step_expected_no_reveal,
        "step_correct_no_reveal_count": step_correct_no_reveal,
        "step_no_reveal_correctness_rate": _ratio(step_correct_no_reveal, step_expected_no_reveal),
        "response_gate_wait_expected_count": response_gate_expected,
        "response_gate_wait_correct_count": response_gate_correct,
        "timeline_reveal_efficiency": _ratio(len(set(touched_assets) & opened_set), len(opened_set)),
        "anchor_step_count": anchor_metrics["anchor_step_count"],
        "anchor_step_correct_count": anchor_metrics["anchor_step_correct_count"],
        "anchor_step_correctness_rate": anchor_metrics["anchor_step_correctness_rate"],
        "anchor_missing_expected_reveals": anchor_metrics["anchor_missing_expected_reveals"],
        "anchor_unexpected_reveal_actions": anchor_metrics["anchor_unexpected_reveal_actions"],
        "anchor_failed_no_reveal_count": anchor_metrics["anchor_failed_no_reveal_count"],
    }


def _anchor_metrics(
    timeline: list[dict[str, Any]],
    step_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Score only timeline steps explicitly marked as decision anchors."""
    anchor_rows = [
        (step, row)
        for step, row in zip(timeline, step_rows)
        if step.get("anchor_check")
    ]
    missing_expected = [
        item
        for _step, row in anchor_rows
        for item in row["missing_expected_reveals"]
    ]
    unexpected_actions = [
        item
        for _step, row in anchor_rows
        for item in row["unexpected_reveal_actions"]
    ]
    failed_no_reveal = sum(
        1
        for step, row in anchor_rows
        if step.get("expected_no_reveal") and row["opened_assets"]
    )
    correct = 0
    for step, row in anchor_rows:
        if step.get("expected_no_reveal"):
            correct += int(not row["opened_assets"])
            continue
        if row["action_constraints_declared"]:
            correct += int(
                not row["missing_expected_reveals"]
                and not row["unexpected_reveal_actions"]
            )
        else:
            correct += 1
    return {
        "anchor_step_count": len(anchor_rows),
        "anchor_step_correct_count": correct,
        "anchor_step_correctness_rate": _ratio(correct, len(anchor_rows)),
        "anchor_missing_expected_reveals": missing_expected,
        "anchor_unexpected_reveal_actions": unexpected_actions,
        "anchor_failed_no_reveal_count": failed_no_reveal,
    }


def _dedupe_reveal_actions(actions: Any) -> list[dict[str, str]]:
    """De-duplicate compact reveal-action dictionaries in timeline order."""
    seen: set[str] = set()
    deduped: list[dict[str, str]] = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        key = json.dumps(action, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(action)
    return deduped


def _sum_gate_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate gate metrics from per-step rows."""
    decision_points = sum(int(row["gate_decision_point_count"]) for row in rows)
    reveal_option_total = sum(
        int(row["gate_eligible_reveal_option_total"]) for row in rows
    )
    decision_space_total = sum(
        int(row["gate_reveal_decision_space_total"]) for row in rows
    )
    narrowing_total = sum(float(row["gate_narrowing_rate_total"]) for row in rows)
    buckets = Counter[str]()
    reasons = Counter[str]()
    for row in rows:
        buckets.update(row["gate_eligible_bucket_counts"])
        reasons.update(row["rejection_reason_counts"])
    return {
        "decision_point_count": decision_points,
        "eligible_reveal_option_total": reveal_option_total,
        "reveal_decision_space_total": decision_space_total,
        "narrowing_rate_total": narrowing_total,
        "reveal_decision_space_avg": _average(decision_space_total, decision_points),
        "eligible_reveal_options_avg": _average(reveal_option_total, decision_points),
        "narrowing_rate": _average(narrowing_total, decision_points),
        "eligible_bucket_counts": {
            bucket: buckets.get(bucket, 0)
            for bucket in ("zero", "one", "two_plus")
        },
        "rejection_reason_counts": dict(sorted(reasons.items())),
    }


def _first_reveal_tick(rows: list[dict[str, Any]]) -> int | None:
    """Return the first 1-based timeline tick that opened an asset/config."""
    for index, row in enumerate(rows, start=1):
        if row["opened_assets"]:
            return index
    return None


def _source_traceability_status(scenario: dict[str, Any], timeline: list[dict[str, Any]]) -> str:
    """Return whether every full-process step declares source traceability."""
    if not timeline:
        return "missing"
    for step in timeline:
        source_refs = step.get("source_refs")
        if not isinstance(source_refs, list) or not source_refs:
            return "missing"
        for source_ref in source_refs:
            if not isinstance(source_ref, dict):
                return "missing"
            if not source_ref.get("reference_id") or not source_ref.get("exactness_level"):
                return "missing"
    return "declared"


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


def _prior_is_healthy_for_comparison(decision_events: list[dict[str, Any]]) -> bool:
    """Return whether controller traces show a usable prior for this step.

    A degraded prior is a runtime fault condition, not an ablation result, so
    those steps must not contribute to the prior-influence numerator or
    denominator.
    """
    if not decision_events:
        return False
    for event in decision_events:
        details = event.get("details")
        if not isinstance(details, dict) or details.get("prior_degraded") is not None:
            return False
    return True


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


def _decision_gate_metrics(decision_events: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarise reveal-option narrowing from decision trace details.

    One asset unlock and one configuration variant each count as one reveal
    option. Rejected catalog assets are also counted as options in the trace
    decision space. Variants filtered before scoring are not yet traced.
    """
    decision_space_counts: list[int] = []
    reveal_option_counts: list[int] = []
    narrowing_rates: list[float] = []
    bucket_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    for event in decision_events:
        details = event.get("details")
        if not isinstance(details, dict):
            continue
        eligible_reveal_options = _dict_list(details.get("eligible_reveal_options"))
        raw_rejected = details.get("rejected_assets")
        rejected_assets = raw_rejected if isinstance(raw_rejected, dict) else {}
        if not eligible_reveal_options and not rejected_assets:
            continue
        eligible_count = len(eligible_reveal_options)
        decision_space_count = eligible_count + len(rejected_assets)
        if decision_space_count <= 0:
            continue
        decision_space_counts.append(decision_space_count)
        reveal_option_counts.append(eligible_count)
        narrowing_rates.append(1.0 - (eligible_count / decision_space_count))
        bucket_counts[_eligible_bucket(eligible_count)] += 1
        for reason in rejected_assets.values():
            reason_counts[_rejection_reason_category(reason)] += 1
    decision_point_count = len(decision_space_counts)
    return {
        "decision_point_count": decision_point_count,
        "eligible_reveal_option_total": sum(reveal_option_counts),
        "reveal_decision_space_total": sum(decision_space_counts),
        "narrowing_rate_total": round(sum(narrowing_rates), 6),
        "reveal_decision_space_avg": _average(
            sum(decision_space_counts),
            decision_point_count,
        ),
        "eligible_reveal_options_avg": _average(
            sum(reveal_option_counts),
            decision_point_count,
        ),
        "narrowing_rate": _average(sum(narrowing_rates), decision_point_count),
        "eligible_bucket_counts": {
            bucket: bucket_counts.get(bucket, 0)
            for bucket in ("zero", "one", "two_plus")
        },
        "rejection_reason_counts": dict(sorted(reason_counts.items())),
    }


def _dict_list(value: object) -> list[dict[str, Any]]:
    """Return only dictionary items from a trace list field."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _eligible_bucket(eligible_count: int) -> str:
    """Return the coarse gate outcome bucket used in the report."""
    if eligible_count <= 0:
        return "zero"
    if eligible_count == 1:
        return "one"
    return "two_plus"


def _rejection_reason_category(reason: object) -> str:
    """Map detailed controller rejection text into stable report categories."""
    text = str(reason).lower()
    if "missing dependencies" in text:
        return "dependency_not_satisfied"
    if "already" in text:
        return "already_revealed"
    if "not ready" in text or "unavailable" in text or "runtime" in text:
        return "not_ready_or_unavailable"
    if "unlock cap" in text:
        return "exposure_budget_reached"
    if "low gain" in text or "redundant" in text:
        return "redundant_or_low_gain"
    if "not an internal asset" in text or "does not match" in text:
        return "out_of_scope_or_no_signal"
    return "other"


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
    prior_influenced_steps = sum(
        int(row.get("prior_influenced_step_count", 1 if row["prior_influenced"] else 0))
        for row in rows
    )
    prior_comparison_steps = sum(
        int(row.get("prior_comparison_step_count", row.get("step_count", 1)))
        for row in rows
    )
    gate_decision_points = sum(int(row["gate_decision_point_count"]) for row in rows)
    gate_eligible_reveal_options = sum(
        int(row["gate_eligible_reveal_option_total"]) for row in rows
    )
    gate_reveal_decision_space = sum(
        int(row["gate_reveal_decision_space_total"]) for row in rows
    )
    gate_narrowing_total = sum(float(row["gate_narrowing_rate_total"]) for row in rows)
    gate_bucket_counts = Counter[str]()
    rejection_reason_counts = Counter[str]()
    for row in rows:
        gate_bucket_counts.update(row["gate_eligible_bucket_counts"])
        rejection_reason_counts.update(row["rejection_reason_counts"])
    rejection_total = sum(rejection_reason_counts.values())
    step_count = sum(int(row.get("step_count", 1)) for row in rows)
    step_expected_no_reveal = sum(int(row.get("step_expected_no_reveal_count", 0)) for row in rows)
    step_correct_no_reveal = sum(int(row.get("step_correct_no_reveal_count", 0)) for row in rows)
    response_gate_expected = sum(int(row.get("response_gate_wait_expected_count", 0)) for row in rows)
    response_gate_correct = sum(int(row.get("response_gate_wait_correct_count", 0)) for row in rows)
    anchor_steps = sum(int(row.get("anchor_step_count", 0)) for row in rows)
    anchor_steps_correct = sum(int(row.get("anchor_step_correct_count", 0)) for row in rows)
    anchor_missing_expected = sum(len(row.get("anchor_missing_expected_reveals", [])) for row in rows)
    anchor_unexpected_reveals = sum(len(row.get("anchor_unexpected_reveal_actions", [])) for row in rows)
    anchor_failed_no_reveal = sum(int(row.get("anchor_failed_no_reveal_count", 0)) for row in rows)
    timeline_efficiency_rows = [
        float(row["timeline_reveal_efficiency"])
        for row in rows
        if "timeline_reveal_efficiency" in row
    ]
    source_traceability_declared = sum(
        1 for row in rows if row.get("source_traceability_status") == "declared"
    )
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
        "step_count": step_count,
        "step_expected_no_reveal_count": step_expected_no_reveal,
        "step_correct_no_reveal_count": step_correct_no_reveal,
        "step_no_reveal_correctness_rate": _ratio(step_correct_no_reveal, step_expected_no_reveal),
        "response_gate_wait_expected_count": response_gate_expected,
        "response_gate_wait_correct_count": response_gate_correct,
        "response_gate_wait_correctness_rate": _ratio(response_gate_correct, response_gate_expected),
        "anchor_step_count": anchor_steps,
        "anchor_step_correct_count": anchor_steps_correct,
        "anchor_step_correctness_rate": _ratio(anchor_steps_correct, anchor_steps),
        "anchor_missing_expected_reveal_count": anchor_missing_expected,
        "anchor_unexpected_reveal_count": anchor_unexpected_reveals,
        "anchor_failed_no_reveal_count": anchor_failed_no_reveal,
        "timeline_reveal_efficiency_avg": (
            round(sum(timeline_efficiency_rows) / len(timeline_efficiency_rows), 6)
            if timeline_efficiency_rows
            else None
        ),
        "source_traceability_declared_rate": _ratio(source_traceability_declared, len(rows)),
        "prior_influenced_scenario_count": prior_influenced,
        "prior_influence_scenario_rate": _ratio(prior_influenced, len(rows)),
        "prior_influenced_step_count": prior_influenced_steps,
        "prior_comparison_step_count": prior_comparison_steps,
        "prior_influence_rate": _ratio(prior_influenced_steps, prior_comparison_steps),
        "gate_decision_point_count": gate_decision_points,
        "gate_reveal_decision_space_total": gate_reveal_decision_space,
        "gate_eligible_reveal_option_total": gate_eligible_reveal_options,
        "gate_reveal_decision_space_avg": _average(
            gate_reveal_decision_space,
            gate_decision_points,
        ),
        "gate_eligible_reveal_options_avg": _average(
            gate_eligible_reveal_options,
            gate_decision_points,
        ),
        "gate_narrowing_rate": _average(gate_narrowing_total, gate_decision_points),
        "gate_eligible_bucket_counts": {
            bucket: gate_bucket_counts.get(bucket, 0)
            for bucket in ("zero", "one", "two_plus")
        },
        "gate_eligible_bucket_rates": {
            bucket: _ratio(gate_bucket_counts.get(bucket, 0), gate_decision_points)
            for bucket in ("zero", "one", "two_plus")
        },
        "rejection_reason_counts": dict(sorted(rejection_reason_counts.items())),
        "rejection_reason_rates": {
            reason: _ratio(count, rejection_total)
            for reason, count in sorted(rejection_reason_counts.items())
        },
        "choice_signal_eligible_count": len(choice_signals),
        "choice_signal_count": len(resolved_choice_signals),
        "resolved_choice_rate": _ratio(len(resolved_choice_signals), len(choice_signals)),
        "choice_signal_counts": choice_signal_counts,
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


def _average(numerator: float, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
