#!/usr/bin/env python3
"""Evaluate ATT&CK group technique recommendations on replay scenarios.

The evaluator treats each scenario's ordered techniques as a small validation
trace. For every prefix, it asks the active prior for recommendations and checks
paper-style recall, specificity, and accuracy over ATT&CK technique families.

Example:
    python scripts/evaluation/attack_group_prior_recommendation.py tests/fixtures/reveal_policy_scenarios.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from libs.common.attack import technique_family_set
from libs.common.config import RuntimeConfig
from libs.common.iterables import dedupe_preserve
from scripts.evaluation.charts import write_prior_recommendation_chart
from scripts.evaluation.reveal_policy import load_scenarios
from services.controller.repository import FileAttackGroupTechniquePriorRepository


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate ATT&CK group prior recommendations on scenario traces.")
    parser.add_argument("scenario_file", type=Path)
    parser.add_argument("--prior", type=Path, default=Path("data/technique_prior/attack_group_technique_prior.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = evaluate_prior_recommendations(
        scenario_file=args.scenario_file,
        prior_path=args.prior,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{text}\n", encoding="utf-8")
        write_prior_recommendation_chart(report, args.output.with_suffix(".svg"))
    else:
        print(text)
    return 0 if report["ok"] else 1


def evaluate_prior_recommendations(
    *,
    scenario_file: Path,
    prior_path: Path,
    config: RuntimeConfig | None = None,
) -> dict[str, Any]:
    """Return family-aware paper-style recall, specificity, and accuracy.

    Example:
        future T1548.003 and recommended T1548 -> recall hit because both share family T1548.
    """
    scenarios = load_scenarios(scenario_file)
    traces: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for item in scenarios:
        scenario_id = str(item.get("scenario_id", "scenario"))
        reason = _prior_eval_exclusion_reason(item)
        if reason is not None:
            excluded.append({"scenario_id": scenario_id, "reason": reason})
            continue
        traces.append({"scenario_id": scenario_id, "techniques": _scenario_techniques(item)})
    trace_report = evaluate_trace_recommendations(
        traces=traces,
        prior_path=prior_path,
        config=config,
    )
    return {
        "schema_version": "v1",
        "ok": trace_report["metrics"]["prefix_count"] > 0 and trace_report["metrics"]["degraded_reason"] is None,
        "scenario_file": str(scenario_file),
        "prior": str(prior_path),
        "top_k": trace_report["top_k"],
        "support_threshold": trace_report["support_threshold"],
        "evaluation_match": "technique_family",
        "technique_family_universe_size": trace_report["technique_family_universe_size"],
        "trace_count": len(traces),
        "excluded_scenarios": excluded,
        "metrics": trace_report["metrics"],
    }


def evaluate_trace_recommendations(
    *,
    traces: list[dict[str, Any]],
    prior_path: Path,
    config: RuntimeConfig | None = None,
) -> dict[str, Any]:
    """Evaluate ordered technique traces against the active group prior.

    `traces` is intentionally small and generic so scenario replay and public
    dataset validation can share one metric implementation.
    """
    runtime_config = config or RuntimeConfig.from_env()
    metrics = _evaluate_trace_prefixes(
        traces,
        prior_path,
        top_k=runtime_config.recommendation_top_k,
        support_threshold=runtime_config.recommendation_support_threshold,
    )
    technique_universe = technique_family_set(_technique_universe_from_prior(prior_path))
    return {
        "top_k": runtime_config.recommendation_top_k,
        "support_threshold": runtime_config.recommendation_support_threshold,
        "evaluation_match": "technique_family",
        "technique_family_universe_size": len(technique_universe),
        "trace_count": len(traces),
        "metrics": metrics,
    }


def _evaluate_trace_prefixes(
    traces: list[dict[str, Any]],
    prior_path: Path,
    *,
    top_k: int,
    support_threshold: float,
) -> dict[str, Any]:
    repository = FileAttackGroupTechniquePriorRepository(prior_path)
    technique_universe = technique_family_set(_technique_universe_from_prior(prior_path))
    prefix_count = 0
    true_positive_total = 0
    false_positive_total = 0
    true_negative_total = 0
    false_negative_total = 0
    prefix_hit_total = 0
    source_rows: list[dict[str, Any]] = []

    for trace in traces:
        techniques = trace["techniques"]
        scenario_prefixes = 0
        scenario_tp = 0
        scenario_fp = 0
        scenario_tn = 0
        scenario_fn = 0
        for index in range(1, len(techniques)):
            observed = technique_family_set(techniques[:index])
            future = technique_family_set(techniques[index:])
            recommendations = repository.recommend(
                set(techniques[:index]),
                top_k=top_k,
                support_threshold=support_threshold,
            )
            recommended = technique_family_set(recommendations)
            evaluation_universe = technique_universe | observed | future | recommended
            relevant_universe = evaluation_universe - observed
            positives = future & relevant_universe
            negatives = relevant_universe - positives
            true_positives = len(recommended & positives)
            false_positives = len(recommended & negatives)
            false_negatives = len(positives - recommended)
            true_negatives = len(negatives - recommended)

            prefix_count += 1
            scenario_prefixes += 1
            true_positive_total += true_positives
            false_positive_total += false_positives
            true_negative_total += true_negatives
            false_negative_total += false_negatives
            scenario_tp += true_positives
            scenario_fp += false_positives
            scenario_tn += true_negatives
            scenario_fn += false_negatives
            if true_positives:
                prefix_hit_total += 1

        source_rows.append(
            {
                "scenario_id": trace["scenario_id"],
                "technique_count": len(techniques),
                "prefix_count": scenario_prefixes,
                # Keep confusion-count internals out of the report; the paper-facing
                # metrics below are recall, specificity, and accuracy.
                # "true_positive": scenario_tp,
                # "false_positive": scenario_fp,
                # "true_negative": scenario_tn,
                # "false_negative": scenario_fn,
                "recall": _ratio(scenario_tp, scenario_tp + scenario_fn),
                "specificity": _ratio(scenario_tn, scenario_tn + scenario_fp),
                "accuracy": _ratio(
                    scenario_tp + scenario_tn,
                    scenario_tp + scenario_fp + scenario_tn + scenario_fn,
                ),
            }
        )

    return {
        "evaluation_match": "technique_family",
        "support_threshold": support_threshold,
        "degraded_reason": repository.degraded_reason,
        "prefix_count": prefix_count,
        # "true_positive": true_positive_total,
        # "false_positive": false_positive_total,
        # "true_negative": true_negative_total,
        # "false_negative": false_negative_total,
        "hit_rate_at_k": _ratio(prefix_hit_total, prefix_count),
        "recall": _ratio(true_positive_total, true_positive_total + false_negative_total),
        "specificity": _ratio(true_negative_total, true_negative_total + false_positive_total),
        "accuracy": _ratio(
            true_positive_total + true_negative_total,
            true_positive_total + false_positive_total + true_negative_total + false_negative_total,
        ),
        "source_breakdown": source_rows,
    }


def _technique_universe_from_prior(path: Path) -> set[str]:
    """Return all known ATT&CK techniques from the prior file.

    Example:
        groups=[{"techniques":["T1190", "T1105"]}] -> {"T1190", "T1105"}
    """
    if not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    groups = payload.get("groups") if isinstance(payload, dict) else None
    if not isinstance(groups, list):
        return set()
    return {
        technique
        for group in groups
        if isinstance(group, dict)
        for technique in group.get("techniques", [])
        if isinstance(technique, str) and technique
    }


def _scenario_techniques(scenario: dict[str, Any]) -> list[str]:
    profile = scenario.get("profile")
    if isinstance(profile, dict):
        return _dedupe_strings(profile.get("recent_techniques", []))
    events = scenario.get("evidence_sequence")
    if not isinstance(events, list):
        return []
    return _dedupe_strings(
        event.get("technique") or event.get("tech_id")
        for event in events
        if isinstance(event, dict)
    )


def _prior_eval_exclusion_reason(scenario: dict[str, Any]) -> str | None:
    """Return why a scenario is not suitable for prior recommendation scoring.

    Example:
        {"expected_no_reveal": true} -> "no-reveal scenario"
    """
    if scenario.get("expected_no_reveal") is True:
        return "no-reveal scenario"
    if scenario.get("boundary") is True:
        return "boundary scenario"
    return None


def _dedupe_strings(values: Any) -> list[str]:
    iterable = values if not isinstance(values, (str, bytes)) else []
    if iterable is None:
        iterable = []
    return dedupe_preserve(value for value in iterable if isinstance(value, str) and value)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
