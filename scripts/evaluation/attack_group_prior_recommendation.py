#!/usr/bin/env python3
"""Evaluate ATT&CK group technique recommendations on replay scenarios.

The evaluator treats each scenario's ordered techniques as a small validation
trace. For every prefix, it asks the active prior for recommendations and checks
candidate-prior quality over ATT&CK technique families. K is the number of
similar ATT&CK groups used by the prior, not the number of emitted techniques.

Example:
    python scripts/evaluation/attack_group_prior_recommendation.py \
        tests/fixtures/reveal_policy_main_scenarios.json \
        tests/fixtures/reveal_policy_scenarios.json
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

DEFAULT_K_SWEEP = (5, 10, 20, 40)
PREFIX_LENGTH_BUCKETS = (
    ("short_1_2", "1-2 observed technique families", 1, 2),
    ("medium_3_4", "3-4 observed technique families", 3, 4),
    ("long_5_plus", "5+ observed technique families", 5, None),
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate ATT&CK group prior recommendations on scenario traces.")
    parser.add_argument("scenario_files", type=Path, nargs="+")
    parser.add_argument("--prior", type=Path, default=Path("data/technique_prior/attack_group_technique_prior.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = evaluate_prior_recommendations(
        scenario_files=args.scenario_files,
        prior_path=args.prior,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{text}\n", encoding="utf-8")
        write_prior_recommendation_chart(report, args.output.with_suffix(".png"))
    else:
        print(text)
    return 0 if report["ok"] else 1


def evaluate_prior_recommendations(
    *,
    scenario_file: Path | None = None,
    scenario_files: list[Path] | tuple[Path, ...] | None = None,
    prior_path: Path,
    config: RuntimeConfig | None = None,
) -> dict[str, Any]:
    """Return family-aware paper-style recall, specificity, and accuracy.

    Example:
        future T1548.003 and recommended T1548 -> recall hit because both share family T1548.
    """
    files = list(scenario_files or ([scenario_file] if scenario_file is not None else []))
    if not files:
        raise ValueError("at least one scenario file is required")
    traces: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for file in files:
        for item in load_scenarios(file):
            scenario_id = str(item.get("scenario_id", "scenario"))
            reason = _prior_eval_exclusion_reason(item)
            if reason is not None:
                excluded.append({"scenario_id": scenario_id, "scenario_file": str(file), "reason": reason})
                continue
            traces.append({"scenario_id": scenario_id, "scenario_file": str(file), "techniques": _scenario_techniques(item)})
    trace_report = evaluate_trace_recommendations(
        traces=traces,
        prior_path=prior_path,
        config=config,
    )
    return {
        "schema_version": "v1",
        "ok": trace_report["metrics"]["prefix_count"] > 0 and trace_report["metrics"]["degraded_reason"] is None,
        "scenario_files": [str(file) for file in files],
        "prior": str(prior_path),
        "top_k": trace_report["top_k"],
        "support_threshold": trace_report["support_threshold"],
        "evaluation_match": "technique_family",
        "technique_family_universe_size": trace_report["technique_family_universe_size"],
        "trace_count": len(traces),
        "excluded_scenarios": excluded,
        "metrics": trace_report["metrics"],
        "prefix_length_buckets": trace_report["prefix_length_buckets"],
        "k_sweep": trace_report["k_sweep"],
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
    k_sweep = [
        _sweep_metrics(
            top_k=top_k,
            metrics=_evaluate_trace_prefixes(
                traces,
                prior_path,
                top_k=top_k,
                support_threshold=runtime_config.recommendation_support_threshold,
            ),
        )
        for top_k in DEFAULT_K_SWEEP
    ]
    technique_universe = technique_family_set(_technique_universe_from_prior(prior_path))
    return {
        "top_k": runtime_config.recommendation_top_k,
        "support_threshold": runtime_config.recommendation_support_threshold,
        "evaluation_match": "technique_family",
        "technique_family_universe_size": len(technique_universe),
        "trace_count": len(traces),
        "metrics": metrics,
        "prefix_length_buckets": _evaluate_trace_prefix_length_buckets(
            traces,
            prior_path,
            top_k=runtime_config.recommendation_top_k,
            support_threshold=runtime_config.recommendation_support_threshold,
        ),
        "k_sweep": k_sweep,
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
    reciprocal_rank_total = 0.0
    recommendation_count_total = 0
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
            recommendation_families = dedupe_preserve(
                family
                for technique in recommendations
                for family in technique_family_set([technique])
            )
            recommended = set(recommendation_families)
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
            rank = _first_hit_rank(recommendation_families, positives)
            if rank is not None:
                reciprocal_rank_total += 1 / rank
            recommendation_count_total += len(recommended)

        source_rows.append(
            {
                "scenario_id": trace["scenario_id"],
                "technique_count": len(techniques),
                "prefix_count": scenario_prefixes,
                # Keep confusion-count internals out of the report; expose the
                # derived rates that are useful when reading the JSON.
                # "true_positive": scenario_tp,
                # "false_positive": scenario_fp,
                # "true_negative": scenario_tn,
                # "false_negative": scenario_fn,
                "precision": _ratio(scenario_tp, scenario_tp + scenario_fp),
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
        "precision": _ratio(true_positive_total, true_positive_total + false_positive_total),
        "recall": _ratio(true_positive_total, true_positive_total + false_negative_total),
        "mrr": round(reciprocal_rank_total / prefix_count, 6) if prefix_count else 0.0,
        "recommendation_count_avg": round(recommendation_count_total / prefix_count, 6) if prefix_count else 0.0,
        "specificity": _ratio(true_negative_total, true_negative_total + false_positive_total),
        "accuracy": _ratio(
            true_positive_total + true_negative_total,
            true_positive_total + false_positive_total + true_negative_total + false_negative_total,
        ),
        "source_breakdown": source_rows,
    }


def _sweep_metrics(*, top_k: int, metrics: dict[str, Any]) -> dict[str, Any]:
    """Return compact metrics for one prior-neighbor K value."""
    return {
        "top_k": top_k,
        "prefix_count": int(metrics.get("prefix_count", 0) or 0),
        "hit_rate_at_k": float(metrics.get("hit_rate_at_k", 0.0) or 0.0),
        "precision": float(metrics.get("precision", 0.0) or 0.0),
        "recall": float(metrics.get("recall", 0.0) or 0.0),
        "mrr": float(metrics.get("mrr", 0.0) or 0.0),
        "recommendation_count_avg": float(metrics.get("recommendation_count_avg", 0.0) or 0.0),
    }


def _evaluate_trace_prefix_length_buckets(
    traces: list[dict[str, Any]],
    prior_path: Path,
    *,
    top_k: int,
    support_threshold: float,
) -> list[dict[str, Any]]:
    """Return Hit/Recall/MRR split by observed prefix length."""
    repository = FileAttackGroupTechniquePriorRepository(prior_path)
    buckets = {
        bucket_id: {
            "bucket": bucket_id,
            "label": label,
            "prefix_min": min_len,
            "prefix_max": max_len,
            "prefix_count": 0,
            "prefix_hit_total": 0,
            "true_positive_total": 0,
            "false_negative_total": 0,
            "reciprocal_rank_total": 0.0,
            "future_technique_total": 0,
        }
        for bucket_id, label, min_len, max_len in PREFIX_LENGTH_BUCKETS
    }
    for trace in traces:
        techniques = trace["techniques"]
        for index in range(1, len(techniques)):
            observed = technique_family_set(techniques[:index])
            future = technique_family_set(techniques[index:])
            bucket_id = _prefix_length_bucket(len(observed))
            if bucket_id is None:
                continue
            bucket = buckets[bucket_id]
            recommendations = repository.recommend(
                set(techniques[:index]),
                top_k=top_k,
                support_threshold=support_threshold,
            )
            recommendation_families = dedupe_preserve(
                family
                for technique in recommendations
                for family in technique_family_set([technique])
            )
            recommended = set(recommendation_families)
            true_positives = len(recommended & future)
            false_negatives = len(future - recommended)
            rank = _first_hit_rank(recommendation_families, future)
            bucket["prefix_count"] += 1
            bucket["prefix_hit_total"] += int(true_positives > 0)
            bucket["true_positive_total"] += true_positives
            bucket["false_negative_total"] += false_negatives
            bucket["reciprocal_rank_total"] += 0.0 if rank is None else 1 / rank
            bucket["future_technique_total"] += len(future)
    rows: list[dict[str, Any]] = []
    for bucket_id, _label, _min_len, _max_len in PREFIX_LENGTH_BUCKETS:
        bucket = buckets[bucket_id]
        prefix_count = int(bucket["prefix_count"])
        rows.append(
            {
                "bucket": bucket["bucket"],
                "label": bucket["label"],
                "prefix_min": bucket["prefix_min"],
                "prefix_max": bucket["prefix_max"],
                "prefix_count": prefix_count,
                "hit_rate_at_k": _ratio(int(bucket["prefix_hit_total"]), prefix_count),
                "recall": _ratio(
                    int(bucket["true_positive_total"]),
                    int(bucket["true_positive_total"]) + int(bucket["false_negative_total"]),
                ),
                "mrr": round(float(bucket["reciprocal_rank_total"]) / prefix_count, 6) if prefix_count else 0.0,
                "future_technique_count_avg": round(float(bucket["future_technique_total"]) / prefix_count, 6) if prefix_count else 0.0,
            }
        )
    return rows


def _prefix_length_bucket(observed_family_count: int) -> str | None:
    """Return the metric bucket for one observed prefix length."""
    for bucket_id, _label, min_len, max_len in PREFIX_LENGTH_BUCKETS:
        if observed_family_count >= min_len and (max_len is None or observed_family_count <= max_len):
            return bucket_id
    return None


def _first_hit_rank(recommendation_families: list[str], positives: set[str]) -> int | None:
    """Return the 1-based rank of the first recommended future technique family."""
    for index, family in enumerate(recommendation_families, start=1):
        if family in positives:
            return index
    return None


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
    if isinstance(events, list):
        return _dedupe_strings(
            event.get("technique") or event.get("tech_id")
            for event in events
            if isinstance(event, dict)
        )
    timeline = scenario.get("timeline")
    if isinstance(timeline, list):
        return _dedupe_strings(
            event.get("technique") or event.get("tech_id")
            for step in timeline
            if isinstance(step, dict)
            for event in step.get("new_evidence", [])
            if isinstance(event, dict)
        )
    return _dedupe_strings(
        []
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
