from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.evaluation.attack_group_prior_recommendation import evaluate_prior_recommendations


pytestmark = pytest.mark.unit


def test_attack_group_prior_recommendation_reports_recall_precision_and_stability(
    tmp_path: Path,
) -> None:
    prior = tmp_path / "prior.json"
    prior.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "method": "attack_group_technique_collaborative_filtering",
                "groups": [
                    {
                        "group_id": "G0001",
                        "name": "Fixture Group",
                        "techniques": ["T1190", "T1105", "T1608"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    scenarios = tmp_path / "scenarios.jsonl"
    scenarios.write_text(
        json.dumps(
            {
                "scenario_id": "web-download-chain",
                "evidence_sequence": [
                    {"technique": "T1190", "evidence_id": "e1"},
                    {"technique": "T1105", "evidence_id": "e2"},
                    {"technique": "T1608", "evidence_id": "e3"},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    report = evaluate_prior_recommendations(
        scenario_file=scenarios,
        prior_path=prior,
        top_k=5,
        thresholds=(0.0,),
    )

    metrics = report["metrics_by_threshold"]["0.0"]
    assert report["ok"] is True
    assert metrics["prefix_count"] == 2
    assert metrics["recall_at_k"] == 1.0
    assert metrics["precision_at_k"] == 1.0
    assert metrics["stability"] is not None


def test_attack_group_prior_recommendation_reports_degraded_missing_prior(
    tmp_path: Path,
) -> None:
    scenarios = tmp_path / "scenarios.jsonl"
    scenarios.write_text(
        json.dumps(
            {
                "scenario_id": "web-download-chain",
                "evidence_sequence": [
                    {"technique": "T1190", "evidence_id": "e1"},
                    {"technique": "T1105", "evidence_id": "e2"},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    report = evaluate_prior_recommendations(
        scenario_file=scenarios,
        prior_path=tmp_path / "missing.json",
        top_k=5,
        thresholds=(0.0,),
    )

    metrics = report["metrics_by_threshold"]["0.0"]
    assert report["ok"] is False
    assert metrics["prefix_count"] == 1
    assert "missing" in metrics["degraded_reason"]


def test_attack_group_prior_recommendation_threshold_sensitivity_and_singletons(
    tmp_path: Path,
) -> None:
    prior = tmp_path / "prior.json"
    prior.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "method": "attack_group_technique_collaborative_filtering",
                "groups": [
                    {
                        "group_id": "G0001",
                        "name": "Fixture Group",
                        "techniques": ["T1190", "T1105"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    scenarios = tmp_path / "scenarios.jsonl"
    scenarios.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "scenario_id": "web-download-chain",
                        "evidence_sequence": [
                            {"technique": "T1190", "evidence_id": "e1"},
                            {"technique": "T1105", "evidence_id": "e2"},
                        ],
                    }
                ),
                json.dumps(
                    {
                        "scenario_id": "single-technique-is-not-a-prefix",
                        "evidence_sequence": [
                            {"technique": "T1083", "evidence_id": "e3"},
                        ],
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    report = evaluate_prior_recommendations(
        scenario_file=scenarios,
        prior_path=prior,
        top_k=5,
        thresholds=(0.0, 0.99),
    )

    loose = report["metrics_by_threshold"]["0.0"]
    strict = report["metrics_by_threshold"]["0.99"]
    assert report["ok"] is True
    assert loose["prefix_count"] == 1
    assert loose["recall_at_k"] == 1.0
    assert strict["recall_at_k"] == 0.0
    assert strict["precision_at_k"] == 0.0
