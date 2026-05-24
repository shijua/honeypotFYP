#!/usr/bin/env python3
"""Evaluate ATT&CK group technique recommendations on replay scenarios.

The evaluator treats each scenario's ordered techniques as a small validation
trace. For every prefix, it asks the active prior for recommendations and checks
whether later scenario techniques appear in the top-K list.

Example:
    python scripts/evaluation/attack_group_prior_recommendation.py tests/fixtures/reveal_policy_scenarios.jsonl
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

from scripts.evaluation.reveal_policy import load_scenarios
from services.controller.repository import FileAttackGroupTechniquePriorRepository


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate ATT&CK group prior recommendations on scenario traces.")
    parser.add_argument("scenario_file", type=Path)
    parser.add_argument("--prior", type=Path, default=Path("data/technique_prior/attack_group_technique_prior.json"))
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--threshold", type=float, action="append", dest="thresholds")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = evaluate_prior_recommendations(
        scenario_file=args.scenario_file,
        prior_path=args.prior,
        top_k=args.top_k,
        thresholds=tuple(args.thresholds or (0.10, 0.15, 0.20)),
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{text}\n", encoding="utf-8")
    else:
        print(text)
    return 0 if report["ok"] else 1


def evaluate_prior_recommendations(
    *,
    scenario_file: Path,
    prior_path: Path,
    top_k: int = 10,
    thresholds: tuple[float, ...] = (0.10, 0.15, 0.20),
) -> dict[str, Any]:
    """Return Recall@K, Precision@K, and stability for scenario technique traces.

    Example:
        observed prefix ["T1190"] and future ["T1105"] with T1105 recommended -> recall hit.
    """
    scenarios = load_scenarios(scenario_file)
    traces = [
        {"scenario_id": str(item.get("scenario_id", "scenario")), "techniques": _scenario_techniques(item)}
        for item in scenarios
    ]
    results = {
        str(threshold): _evaluate_threshold(traces, prior_path, top_k=top_k, threshold=threshold)
        for threshold in thresholds
    }
    return {
        "schema_version": "v1",
        "ok": any(
            result["prefix_count"] > 0 and result["degraded_reason"] is None
            for result in results.values()
        ),
        "scenario_file": str(scenario_file),
        "prior": str(prior_path),
        "top_k": top_k,
        "trace_count": len(traces),
        "metrics_by_threshold": results,
    }


def _evaluate_threshold(
    traces: list[dict[str, Any]],
    prior_path: Path,
    *,
    top_k: int,
    threshold: float,
) -> dict[str, Any]:
    repository = FileAttackGroupTechniquePriorRepository(prior_path)
    prefix_count = 0
    future_total = 0
    recommendation_total = 0
    hit_total = 0
    stability_scores: list[float] = []
    source_rows: list[dict[str, Any]] = []

    for trace in traces:
        techniques = trace["techniques"]
        previous_recommendations: set[str] | None = None
        scenario_prefixes = 0
        scenario_hits = 0
        for index in range(1, len(techniques)):
            observed = set(techniques[:index])
            future = set(techniques[index:])
            recommendations = repository.recommend(observed, top_k=top_k, support_threshold=threshold)
            recommended = set(recommendations)
            hits = recommended & future

            prefix_count += 1
            scenario_prefixes += 1
            future_total += len(future)
            recommendation_total += len(recommended)
            hit_total += len(hits)
            scenario_hits += len(hits)
            if previous_recommendations is not None:
                stability_scores.append(_jaccard(previous_recommendations, recommended))
            previous_recommendations = recommended

        source_rows.append(
            {
                "scenario_id": trace["scenario_id"],
                "technique_count": len(techniques),
                "prefix_count": scenario_prefixes,
                "hit_count": scenario_hits,
            }
        )

    return {
        "threshold": threshold,
        "degraded_reason": repository.degraded_reason,
        "prefix_count": prefix_count,
        "recall_at_k": _ratio(hit_total, future_total),
        "precision_at_k": _ratio(hit_total, recommendation_total),
        "stability": round(sum(stability_scores) / len(stability_scores), 6) if stability_scores else None,
        "source_breakdown": source_rows,
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


def _dedupe_strings(values: Any) -> list[str]:
    items: list[str] = []
    seen: set[str] = set()
    iterable = values if not isinstance(values, (str, bytes)) else []
    if iterable is None:
        iterable = []
    for value in iterable:
        if isinstance(value, str) and value and value not in seen:
            items.append(value)
            seen.add(value)
    return items


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    return len(left & right) / len(left | right)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
