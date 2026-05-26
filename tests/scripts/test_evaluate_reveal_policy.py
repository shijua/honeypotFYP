from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.evaluation.charts import write_reveal_policy_chart
from scripts.evaluation.reveal_policy import evaluate_reveal_policies, load_scenarios


pytestmark = pytest.mark.unit


def test_reveal_policy_evaluator_compares_baselines(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps(
            [
                {
                    "asset_id": "internal-portal",
                    "asset_name": "Internal Portal",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Discovery"],
                    "dependencies": [],
                    "default_settings": {
                        "selection_profile": {
                            "asset_group": "portal",
                            "covered_techniques": ["T1046"],
                            "telemetry_value": 0.6,
                        }
                    },
                },
                {
                    "asset_id": "finance-share",
                    "asset_name": "Finance Share",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Credential Access", "Collection"],
                    "dependencies": ["internal-portal"],
                    "default_settings": {
                        "selection_profile": {
                            "asset_group": "data-share",
                            "covered_techniques": ["T1552.001", "T1005"],
                            "telemetry_value": 0.9,
                        }
                    },
                },
                {
                    "asset_id": "web-admin-console",
                    "asset_name": "Web Admin Console",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Discovery"],
                    "dependencies": [],
                    "default_settings": {
                        "selection_profile": {
                            "asset_group": "admin-web",
                            "covered_techniques": ["T1046"],
                            "telemetry_value": 0.6,
                        }
                    },
                },
            ]
        ),
        encoding="utf-8",
    )
    prior = tmp_path / "prior.json"
    prior.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                    "method": "attack_group_collaborative_filtering",
                    "groups": [
                        {
                            "group_id": "G0001",
                            "name": "Fixture Group 1",
                            "techniques": ["T1552.001", "T1005"],
                        },
                        {
                            "group_id": "G0002",
                            "name": "Fixture Group 2",
                            "techniques": ["T1552.001", "T1005"],
                        },
                        {
                            "group_id": "G0003",
                            "name": "Fixture Group 3",
                            "techniques": ["T1552.001", "T1005"],
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
                        "scenario_id": "backup-probe",
                        "initial_unlocked_assets": ["internal-portal"],
                        "profile": {
                            "conf_by_technique": {"T1552.001": 0.9},
                            "recent_techniques": ["T1552.001"],
                            "recent_evidence_ids": ["e1"],
                        },
                        "expected_reasonable_assets": ["finance-share"],
                        "expected_hidden_assets": ["web-admin-console"],
                        "useful_followup_assets": ["finance-share"],
                    }
                ),
                json.dumps(
                    {
                        "scenario_id": "sequence-profile",
                        "initial_unlocked_assets": ["internal-portal"],
                        "evidence_sequence": [
                            {
                                "evidence_id": "e2",
                                "technique": "T1552.001",
                                "tactic": "Credential Access",
                                "weight": 0.85,
                            }
                        ],
                        "expected_reasonable_assets": ["finance-share"],
                        "expected_hidden_assets": ["web-admin-console"],
                        "useful_followup_assets": ["finance-share"],
                    }
                ),
                json.dumps(
                    {
                        "scenario_id": "scanner-no-reveal",
                        "profile": {
                            "conf_by_technique": {"T1190": 0.8},
                            "recent_techniques": ["T1190"],
                            "recent_evidence_ids": ["e3"],
                        },
                        "expected_reasonable_assets": [],
                        "expected_hidden_assets": ["finance-share", "web-admin-console"],
                        "useful_followup_assets": [],
                        "expected_no_reveal": True,
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    report = evaluate_reveal_policies(
        scenario_file=scenarios,
        catalog_path=catalog,
        prior_path=prior,
    )

    assert report["ok"] is True
    assert set(report["policies"]) == {
        "passive",
        "all-open",
        "random-eligible",
        "gate-only",
        "top-recommendation",
        "controller",
    }
    assert report["policies"]["controller"]["reveal_correctness"] == 1.0
    assert report["policies"]["controller"]["decision_trace_completeness_rate"] == 1.0
    assert report["policies"]["controller"]["correct_no_reveal_rate"] == 1.0
    assert report["policies"]["controller"]["unlock_reveal_count"] == 2
    assert report["policies"]["controller"]["configuration_reveal_count"] == 0
    assert "prior_influence_rate" in report["policies"]["controller"]
    assert "diagnostic_or_useful_per_reveal" in report["policies"]["controller"]
    assert report["policies"]["passive"]["avg_opened_assets"] == 0
    assert report["policies"]["top-recommendation"]["reveal_correctness"] == 1.0
    assert report["policies"]["random-eligible"]["scenario_count"] == 3
    assert report["policies"]["all-open"]["hidden_violation_rate"] > 0
    assert report["policies"]["all-open"]["irrelevant_reveal_rate"] > 0

    chart_path = tmp_path / "policy.svg"
    write_reveal_policy_chart(report, chart_path)
    chart = chart_path.read_text(encoding="utf-8")
    assert chart.startswith("<?xml") or chart.startswith("<svg")
    assert "Reveal Policy Comparison" in chart


def test_reveal_policy_loader_skips_comments(tmp_path: Path) -> None:
    scenarios = tmp_path / "scenarios.jsonl"
    scenarios.write_text('# comment\n{"scenario_id": "s1"}\n\n', encoding="utf-8")

    assert load_scenarios(scenarios) == [{"scenario_id": "s1"}]
