from __future__ import annotations

from pathlib import Path

import pytest

from scripts.data.build_attack_transition_prior import NormalizedEvent, load_events
from scripts.evaluation.technique_prior import _evaluate_edges, _ranked_scores, evaluate_prior


pytestmark = pytest.mark.unit


def test_evaluate_technique_prior_reports_holdout_metrics(tmp_path: Path) -> None:
    dataset = tmp_path / "events.csv"
    dataset.write_text(
        "case_id,timestamp,technique,tactic\n"
        "case-a,2026-01-01T00:00:00Z,T1110,Credential Access\n"
        "case-a,2026-01-01T00:01:00Z,T1087.001,Discovery\n"
        "case-b,2026-01-01T00:00:00Z,T1110,Credential Access\n"
        "case-b,2026-01-01T00:01:00Z,T1087.001,Discovery\n"
        "case-c,2026-01-01T00:00:00Z,T1190,Initial Access\n"
        "case-c,2026-01-01T00:01:00Z,T1552.001,Credential Access\n",
        encoding="utf-8",
    )
    events, stats = load_events([dataset])

    report = evaluate_prior(events, stats=stats, holdout_percent=50, alpha=0.0, min_support=1, top_k=3, seed="test")

    assert report["trace_count"] == 3
    assert report["train_event_count"] > 0
    assert report["evaluated_edges"] > 0
    assert report["model_mode"] == "hybrid"
    assert "style_mode" not in report
    assert "order2_context_rate" in report
    assert "parent_top1_accuracy" in report
    assert "catalog_filtered_edges" in report
    assert "asset_top1_accuracy" in report
    assert 0 <= report["top1_accuracy"] <= 1
    assert 0 <= report["top3_accuracy"] <= 1


def test_evaluate_technique_prior_can_rank_order1_order2_and_hybrid() -> None:
    transitions = {
        "T1002": {
            "T1003": {"probability": 0.2, "support": 2},
            "T1004": {"probability": 0.5, "support": 2},
        }
    }
    order2_transitions = {
        "T1001|T1002": {
            "T1003": {"probability": 0.9, "support": 2},
        }
    }
    order3_transitions = {
        "T1000|T1001|T1002": {
            "T1003": {"probability": 0.95, "support": 3},
        }
    }

    order1, order1_flags = _ranked_scores(
        transitions,
        order2_transitions,
        order3_transitions,
        history=["T1000", "T1001", "T1002"],
        model_mode="order1",
    )
    order2, order2_flags = _ranked_scores(
        transitions,
        order2_transitions,
        order3_transitions,
        history=["T1000", "T1001", "T1002"],
        model_mode="order2",
    )
    order3, order3_flags = _ranked_scores(
        transitions,
        order2_transitions,
        order3_transitions,
        history=["T1000", "T1001", "T1002"],
        model_mode="order3",
    )
    hybrid, hybrid_flags = _ranked_scores(
        transitions,
        order2_transitions,
        order3_transitions,
        history=["T1000", "T1001", "T1002"],
        model_mode="hybrid",
    )

    assert order1[0] == ("T1004", 0.5)
    assert order2 == [("T1003", 0.9)]
    assert order3 == [("T1003", 0.95)]
    assert hybrid[0] == ("T1003", 0.545)
    assert dict(hybrid)["T1004"] == 0.5
    assert order1_flags["used_order2"] is False
    assert order2_flags["used_order2"] is True
    assert order3_flags["used_order3"] is True
    assert hybrid_flags["had_order2"] is True
    assert hybrid_flags["used_order2"] is True
    assert hybrid_flags["used_order3"] is True


def test_evaluate_technique_prior_reports_parent_and_asset_level_hits() -> None:
    prior = {
        "transitions": {
            "T1000": {
                "T1552": {"probability": 0.8, "support": 2},
                "T1046": {"probability": 0.2, "support": 2},
            }
        },
        "order2_transitions": {},
        "order3_transitions": {},
    }
    trace = [
        NormalizedEvent(case_id="case-a", source_dataset="fixture", technique="T1000", order=0),
        NormalizedEvent(case_id="case-a", source_dataset="fixture", technique="T1552.001", order=1),
    ]

    metrics = _evaluate_edges(
        prior,
        [trace],
        top_k=3,
        model_mode="order1",
        catalog_coverage={"T1552.001": ["finance-share"], "T1552": ["finance-share"]},
    )

    assert metrics["top1_accuracy"] == 0.0
    assert metrics["parent_top1_accuracy"] == 1.0
    assert metrics["catalog_filtered_edges"] == 1
    assert metrics["catalog_top1_accuracy"] == 0.0
    assert metrics["asset_top1_accuracy"] == 1.0
