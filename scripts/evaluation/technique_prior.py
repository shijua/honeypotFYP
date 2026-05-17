#!/usr/bin/env python3
"""Evaluate public ATT&CK transition priors with a case-level holdout split.

This is not model training in the neural-network sense. It estimates how well
the public dataset prior predicts the next labelled technique in held-out traces.

Example:
    python scripts/evaluation/technique_prior.py vendor/datasets --holdout-percent 20
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Literal

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scripts.data.build_attack_transition_prior import BuildStats, NormalizedEvent, build_prior, load_events

ModelMode = Literal["order1", "order2", "order3", "hybrid"]
TOP_KS = (3, 5, 10)


def main() -> int:
    """Run the evaluation and print top-k, MRR, and NLL as JSON."""
    parser = argparse.ArgumentParser(description="Evaluate P(next technique | current technique) on held-out public traces.")
    parser.add_argument("inputs", nargs="+", help="Dataset files, directories, or zip archives.")
    parser.add_argument("--holdout-percent", type=int, default=20)
    parser.add_argument("--alpha", type=float, default=0.1)
    parser.add_argument("--min-support", type=int, default=1)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--count-mode", choices=("trace-balanced", "event-count"), default="trace-balanced")
    parser.add_argument("--global-fallback-weight", type=float, default=0.05)
    parser.add_argument("--model-mode", choices=("order1", "order2", "order3", "hybrid"), default="hybrid")
    parser.add_argument("--seed", default="honeynet")
    args = parser.parse_args()

    events, stats = load_events([Path(item) for item in args.inputs])
    report = evaluate_prior(
        events,
        stats=stats,
        holdout_percent=args.holdout_percent,
        alpha=args.alpha,
        min_support=args.min_support,
        top_k=args.top_k,
        count_mode=args.count_mode,
        global_fallback_weight=args.global_fallback_weight,
        model_mode=args.model_mode,
        seed=args.seed,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


def evaluate_prior(
    events: list[NormalizedEvent],
    *,
    stats: BuildStats,
    holdout_percent: int,
    alpha: float,
    min_support: int,
    top_k: int,
    count_mode: str = "trace-balanced",
    global_fallback_weight: float = 0.05,
    model_mode: ModelMode = "hybrid",
    seed: str = "honeynet",
) -> dict[str, Any]:
    """Train on non-holdout cases and score held-out next-technique edges."""
    if not 1 <= holdout_percent <= 99:
        raise ValueError("holdout_percent must be between 1 and 99")
    traces = _group_traces(events)
    train_events: list[NormalizedEvent] = []
    test_traces: list[list[NormalizedEvent]] = []
    for trace_key, trace_events in traces.items():
        if _is_holdout(trace_key, seed=seed, holdout_percent=holdout_percent):
            test_traces.append(trace_events)
        else:
            train_events.extend(trace_events)

    train_stats = _stats_from_events(train_events, stats)
    prior, build_report = build_prior(
        train_events,
        stats=train_stats,
        alpha=alpha,
        min_support=min_support,
        count_mode=count_mode,  # type: ignore[arg-type]
        global_fallback_weight=global_fallback_weight,
    )
    metrics = _evaluate_edges(
        prior,
        test_traces,
        top_k=top_k,
        model_mode=model_mode,
    )
    return {
        "schema_version": "v1",
        "ok": metrics["evaluated_edges"] > 0,
        "holdout_percent": holdout_percent,
        "top_k": top_k,
        "alpha": alpha,
        "min_support": min_support,
        "count_mode": count_mode,
        "global_fallback_weight": global_fallback_weight,
        "model_mode": model_mode,
        "trace_count": len(traces),
        "train_event_count": len(train_events),
        "labelled_events_used": len(events),
        "skipped_events_without_technique": sum(stats.skipped_without_technique.values()),
        "test_trace_count": len(test_traces),
        "train_transition_count": build_report["transition_count"],
        "source_breakdown": _source_breakdown(test_traces, metrics.pop("_source_metrics")),
        **metrics,
    }


def _group_traces(events: list[NormalizedEvent]) -> dict[tuple[str, str], list[NormalizedEvent]]:
    """Group events by `(source_dataset, case_id)` in attacker-observed order."""
    traces: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        traces[(event.source_dataset, event.case_id)].append(event)
    return {key: sorted(value, key=lambda item: item.sort_key) for key, value in traces.items()}


def _is_holdout(trace_key: tuple[str, str], *, seed: str, holdout_percent: int) -> bool:
    """Deterministically keep whole cases together in train or holdout."""
    digest = hashlib.sha256(f"{seed}:{trace_key[0]}:{trace_key[1]}".encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100 < holdout_percent


def _stats_from_events(events: list[NormalizedEvent], original: BuildStats) -> BuildStats:
    """Rebuild train-split counters while preserving parse diagnostics."""
    stats = BuildStats(parse_errors=list(original.parse_errors))
    for event in events:
        stats.records_seen[event.source_dataset] += 1
        stats.events_used[event.source_dataset] += 1
    return stats


def _evaluate_edges(
    prior: dict[str, Any],
    test_traces: list[list[NormalizedEvent]],
    *,
    top_k: int,
    model_mode: ModelMode,
) -> dict[str, Any]:
    """Score held-out direct-follow edges with top-k, MRR, NLL, and context rates."""
    evaluated = 0
    top1_hits = 0
    top_hits = {k: 0 for k in TOP_KS}
    reciprocal_rank_sum = 0.0
    negative_log_likelihood = 0.0
    unseen_sources = 0
    order2_context_edges = 0
    order2_used_edges = 0
    order3_context_edges = 0
    order3_used_edges = 0
    source_metrics: dict[str, dict[str, int | float]] = defaultdict(_source_metric_row)
    transitions = prior.get("transitions", {})
    order2_transitions = prior.get("order2_transitions", {})
    order3_transitions = prior.get("order3_transitions", {})
    for trace in test_traces:
        history: list[str] = []
        for event in trace:
            if not history:
                history.append(event.technique)
                continue
            if history[-1] == event.technique:
                continue
            ranked_scores, context_flags = _ranked_scores(
                transitions,
                order2_transitions,
                order3_transitions,
                history=history,
                model_mode=model_mode,
            )
            evaluated += 1
            if context_flags["had_order2"]:
                order2_context_edges += 1
            if context_flags["used_order2"]:
                order2_used_edges += 1
            if context_flags["had_order3"]:
                order3_context_edges += 1
            if context_flags["used_order3"]:
                order3_used_edges += 1
            source_row = source_metrics[event.source_dataset]
            source_row["evaluated_edges"] = int(source_row["evaluated_edges"]) + 1
            if not ranked_scores:
                # No transition exists from this history in the trained prior.
                # Count it as unseen and assign a tiny probability for NLL.
                unseen_sources += 1
                negative_log_likelihood += -math.log(1e-12)
                history.append(event.technique)
                continue
            candidates = [technique for technique, _score in ranked_scores]
            probabilities = {technique: score for technique, score in ranked_scores}
            if candidates[0] == event.technique:
                top1_hits += 1
                source_row["top1_hits"] = int(source_row["top1_hits"]) + 1
            for k in TOP_KS:
                if event.technique in candidates[:k]:
                    top_hits[k] += 1
                    source_row[f"top{k}_hits"] = int(source_row[f"top{k}_hits"]) + 1
            if event.technique in candidates:
                reciprocal_rank_sum += 1.0 / (candidates.index(event.technique) + 1)
            negative_log_likelihood += -math.log(max(probabilities.get(event.technique, 0.0), 1e-12))
            history.append(event.technique)

    if evaluated == 0:
        return _empty_metrics(top_k)
    return {
        "evaluated_edges": evaluated,
        "top1_accuracy": _rate(top1_hits, evaluated),
        **{f"top{k}_accuracy": _rate(top_hits[k], evaluated) for k in TOP_KS},
        f"top{top_k}_accuracy": _rate(top1_hits if top_k == 1 else top_hits.get(top_k, 0), evaluated),
        "mrr": _rate(reciprocal_rank_sum, evaluated),
        "mean_negative_log_likelihood": _rate(negative_log_likelihood, evaluated),
        "unseen_source_rate": _rate(unseen_sources, evaluated),
        "order2_context_edges": order2_context_edges,
        "order2_context_rate": _rate(order2_context_edges, evaluated),
        "order2_used_edges": order2_used_edges,
        "order2_used_rate": _rate(order2_used_edges, evaluated),
        "order3_context_edges": order3_context_edges,
        "order3_context_rate": _rate(order3_context_edges, evaluated),
        "order3_used_edges": order3_used_edges,
        "order3_used_rate": _rate(order3_used_edges, evaluated),
        "_source_metrics": dict(source_metrics),
    }


def _ranked_scores(
    transitions: dict[str, dict[str, dict[str, Any]]],
    order2_transitions: dict[str, dict[str, dict[str, Any]]],
    order3_transitions: dict[str, dict[str, dict[str, Any]]],
    *,
    history: list[str],
    model_mode: ModelMode,
) -> tuple[list[tuple[str, float]], dict[str, bool]]:
    """Return ranked next-technique candidates for one history."""
    previous = history[-1]
    previous_previous = history[-2] if len(history) >= 2 else None
    previous2 = history[-3] if len(history) >= 3 else None
    order1_scores = _transition_scores(transitions, previous)
    order2_source = f"{previous_previous}|{previous}" if previous_previous else ""
    order2_scores = _transition_scores(order2_transitions, order2_source)
    order3_source = f"{previous2}|{previous_previous}|{previous}" if previous2 and previous_previous else ""
    order3_scores = _transition_scores(order3_transitions, order3_source)
    flags = {
        "had_order2": bool(order2_scores),
        "used_order2": False,
        "had_order3": bool(order3_scores),
        "used_order3": False,
    }
    if model_mode == "order1":
        scores = order1_scores
    elif model_mode == "order2":
        scores = order2_scores
        flags["used_order2"] = bool(order2_scores)
    elif model_mode == "order3":
        scores = order3_scores
        flags["used_order3"] = bool(order3_scores)
    else:
        scores = _hybrid_scores(order1_scores, order2_scores, order3_scores)
        flags["used_order2"] = bool(order2_scores)
        flags["used_order3"] = bool(order3_scores)
    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    return ranked, flags


def _probability(payload: dict[str, Any]) -> float:
    """Read one transition probability payload safely."""
    try:
        return float(payload.get("probability", 0.0))
    except (TypeError, ValueError):
        return 0.0


def _source_breakdown(test_traces: list[list[NormalizedEvent]], source_metrics: dict[str, dict[str, int | float]]) -> dict[str, dict[str, float | int]]:
    """Return per-source holdout metrics for mixed-dataset comparisons."""
    trace_counts = Counter(trace[0].source_dataset for trace in test_traces if trace)
    breakdown: dict[str, dict[str, float | int]] = {}
    for source, metrics in sorted(source_metrics.items()):
        evaluated = int(metrics.get("evaluated_edges", 0) or 0)
        breakdown[source] = {
            "test_trace_count": trace_counts[source],
            "evaluated_edges": evaluated,
            "top1_accuracy": _metric_rate(metrics, "top1_hits", evaluated),
            **{f"top{k}_accuracy": _metric_rate(metrics, f"top{k}_hits", evaluated) for k in TOP_KS},
        }
    return breakdown


def _transition_scores(
    transitions: dict[str, dict[str, dict[str, Any]]],
    source: str,
) -> dict[str, float]:
    """Return destination probabilities for one transition source technique."""
    return {
        technique: _probability(payload)
        for technique, payload in transitions.get(source, {}).items()
    }


def _hybrid_scores(
    order1_scores: dict[str, float],
    order2_scores: dict[str, float],
    order3_scores: dict[str, float],
) -> dict[str, float]:
    """Blend higher-order context without lowering lower-order scores."""
    scores = dict(order1_scores)
    for technique in set(order1_scores) | set(order2_scores):
        base = order1_scores.get(technique, 0.0)
        scores[technique] = max(base, (0.75 * base) + (0.25 * order2_scores.get(technique, 0.0)))
    for technique in set(scores) | set(order2_scores) | set(order3_scores):
        base = scores.get(technique, 0.0)
        hybrid = (
            (0.45 * order1_scores.get(technique, 0.0))
            + (0.20 * order2_scores.get(technique, 0.0))
            + (0.25 * order3_scores.get(technique, 0.0))
            + (0.10 * base)
        )
        scores[technique] = max(base, hybrid)
    return scores


def _source_metric_row() -> dict[str, int | float]:
    return {"evaluated_edges": 0, "top1_hits": 0, **{f"top{k}_hits": 0 for k in TOP_KS}}


def _empty_metrics(top_k: int) -> dict[str, Any]:
    return {
        "evaluated_edges": 0,
        "top1_accuracy": 0.0,
        **{f"top{k}_accuracy": 0.0 for k in TOP_KS},
        f"top{top_k}_accuracy": 0.0,
        "mrr": 0.0,
        "mean_negative_log_likelihood": 0.0,
        "unseen_source_rate": 0.0,
        "order2_context_edges": 0,
        "order2_context_rate": 0.0,
        "order2_used_edges": 0,
        "order2_used_rate": 0.0,
        "order3_context_edges": 0,
        "order3_context_rate": 0.0,
        "order3_used_edges": 0,
        "order3_used_rate": 0.0,
        "_source_metrics": {},
    }


def _metric_rate(metrics: dict[str, int | float], key: str, total: int) -> float:
    return _rate(float(metrics.get(key, 0) or 0), total)


def _rate(value: float, total: int) -> float:
    return round(value / total, 6) if total else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
