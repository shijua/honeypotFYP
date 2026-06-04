from __future__ import annotations

import json
from pathlib import Path

import pytest

from libs.common.config import RuntimeConfig
from scripts.evaluation.charts import write_prior_recommendation_chart
from scripts.evaluation.attack_group_prior_recommendation import evaluate_prior_recommendations


pytestmark = pytest.mark.unit


def test_attack_group_prior_recommendation_reports_default_paper_metrics(
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
                        "group_id": f"G000{index}",
                        "name": f"Fixture Group {index}",
                        "techniques": ["T1190", "T1105", "T1608"],
                    }
                    for index in range(1, 5)
                ]
                + [
                    {
                        "group_id": "G0099",
                        "name": "Unrelated Group",
                        "techniques": ["T1046"],
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
        config=RuntimeConfig(),
    )

    metrics = report["metrics"]
    assert report["ok"] is True
    assert report["top_k"] == 40
    assert [row["top_k"] for row in report["k_sweep"]] == [5, 10, 20, 40]
    assert "rank_sweep" not in report
    assert report["support_threshold"] == 0.15
    assert report["evaluation_match"] == "technique_family"
    assert report["technique_family_universe_size"] == 4
    assert metrics["prefix_count"] == 2
    assert metrics["hit_rate_at_k"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["mrr"] == 1.0
    assert metrics["specificity"] == 1.0
    assert metrics["accuracy"] == 1.0
    assert metrics["source_breakdown"][0]["precision"] == 1.0
    assert metrics["source_breakdown"][0]["recall"] == 1.0

    chart_path = tmp_path / "prior.png"
    write_prior_recommendation_chart(report, chart_path)


def test_attack_group_prior_recommendation_combines_files_and_timeline_steps(
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
                        "group_id": f"G000{index}",
                        "name": f"Fixture Group {index}",
                        "techniques": ["T1190", "T1105", "T1213"],
                    }
                    for index in range(1, 4)
                ],
            }
        ),
        encoding="utf-8",
    )
    snapshot_scenarios = tmp_path / "snapshot.jsonl"
    snapshot_scenarios.write_text(
        json.dumps(
            {
                "scenario_id": "snapshot-chain",
                "evidence_sequence": [
                    {"technique": "T1190", "evidence_id": "e1"},
                    {"technique": "T1105", "evidence_id": "e2"},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    timeline_scenarios = tmp_path / "timeline.json"
    timeline_scenarios.write_text(
        json.dumps(
            [
                {
                    "scenario_id": "timeline-chain",
                    "timeline": [
                        {"step_id": "s1", "new_evidence": [{"technique": "T1190", "evidence_id": "t1"}]},
                        {"step_id": "s2", "new_evidence": [{"technique": "T1213", "evidence_id": "t2"}]},
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )

    report = evaluate_prior_recommendations(
        scenario_files=[timeline_scenarios, snapshot_scenarios],
        prior_path=prior,
        config=RuntimeConfig(),
    )

    assert report["ok"] is True
    assert report["scenario_files"] == [str(timeline_scenarios), str(snapshot_scenarios)]
    assert report["trace_count"] == 2
    assert report["metrics"]["prefix_count"] == 2


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
        config=RuntimeConfig(),
    )

    metrics = report["metrics"]
    assert report["ok"] is False
    assert metrics["prefix_count"] == 1
    assert "missing" in metrics["degraded_reason"]


def test_attack_group_prior_recommendation_ignores_singleton_traces(
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
                        "group_id": f"G000{index}",
                        "name": f"Fixture Group {index}",
                        "techniques": ["T1190", "T1105"],
                    }
                    for index in range(1, 4)
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
        config=RuntimeConfig(),
    )

    metrics = report["metrics"]
    assert report["ok"] is True
    assert metrics["prefix_count"] == 1
    assert metrics["recall"] == 1.0


def test_attack_group_prior_recommendation_matches_subtechnique_family(
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
                        "group_id": f"G000{index}",
                        "name": f"Fixture Group {index}",
                        "techniques": ["T1083", "T1548"],
                    }
                    for index in range(1, 4)
                ],
            }
        ),
        encoding="utf-8",
    )
    scenarios = tmp_path / "scenarios.jsonl"
    scenarios.write_text(
        json.dumps(
            {
                "scenario_id": "family-chain",
                "evidence_sequence": [
                    {"technique": "T1083", "evidence_id": "e1"},
                    {"technique": "T1548.003", "evidence_id": "e2"},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    report = evaluate_prior_recommendations(
        scenario_file=scenarios,
        prior_path=prior,
        config=RuntimeConfig(),
    )

    metrics = report["metrics"]
    assert metrics["recall"] == 1.0


def test_attack_group_prior_recommendation_excludes_no_reveal_scenarios(
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
                        "group_id": f"G000{index}",
                        "name": f"Fixture Group {index}",
                        "techniques": ["T1190", "T1105"],
                    }
                    for index in range(1, 3)
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
                        "scenario_id": "fit-chain",
                        "evidence_sequence": [
                            {"technique": "T1190", "evidence_id": "e1"},
                            {"technique": "T1105", "evidence_id": "e2"},
                        ],
                    }
                ),
                json.dumps(
                    {
                        "scenario_id": "scanner-no-reveal",
                        "expected_no_reveal": True,
                        "profile": {"recent_techniques": ["T1190", "T1105"]},
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
        config=RuntimeConfig(),
    )

    metrics = report["metrics"]
    assert report["trace_count"] == 1
    assert report["excluded_scenarios"][0]["scenario_id"] == "scanner-no-reveal"
    assert report["excluded_scenarios"][0]["scenario_file"] == str(scenarios)
    assert report["excluded_scenarios"][0]["reason"] == "no-reveal scenario"
    assert metrics["prefix_count"] == 1
