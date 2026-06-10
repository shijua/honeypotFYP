from __future__ import annotations

import json
from pathlib import Path

import pytest

from libs.contracts.models import AssetDefinition
import scripts.evaluation.reveal_policy as reveal_policy_module
from scripts.evaluation.charts import write_reveal_policy_chart
from scripts.evaluation.reveal_policy import (
    evaluate_scenario,
    evaluate_reveal_policies,
    format_reveal_policy_report_summary,
    load_scenarios,
    scenario_request,
    scenario_timeline,
)
from scripts.evaluation.reveal_policy_baselines import gate_only_reveals


pytestmark = pytest.mark.unit


def test_gate_only_uses_controller_novelty_ordering_without_prior() -> None:
    assets = [
        AssetDefinition.model_validate(
            {
                "asset_id": "high-confidence-first",
                "asset_name": "High Confidence First",
                "exposure_type": "internal",
                "interaction_level": "medium",
                "covers_tactics": ["Discovery"],
                "dependencies": [],
                "default_settings": {
                    "unlock_signals": {"any_techniques": ["T1083", "T1046"]},
                    "selection_profile": {
                        "asset_group": "first",
                        "covered_techniques": ["T1083"],
                        "telemetry_value": 0.5,
                    },
                },
            }
        ),
        AssetDefinition.model_validate(
            {
                "asset_id": "low-confidence-second",
                "asset_name": "Low Confidence Second",
                "exposure_type": "internal",
                "interaction_level": "medium",
                "covers_tactics": ["Discovery"],
                "dependencies": [],
                "default_settings": {
                    "unlock_signals": {"any_techniques": ["T1083", "T1046"]},
                    "selection_profile": {
                        "asset_group": "second",
                        "covered_techniques": ["T1046"],
                        "telemetry_value": 0.5,
                    },
                },
            }
        ),
    ]
    request = scenario_request(
        {
            "scenario_id": "gate-only-novelty",
            "profile": {
                "conf_by_technique": {"T1083": 0.9, "T1046": 0.1},
                "recent_techniques": ["T1083", "T1046"],
                "recent_evidence_ids": ["e1"],
            },
        }
    )

    opened, actions, events = gate_only_reveals(assets, request, max_reveals=1)

    assert opened == ["low-confidence-second"]
    assert actions == [{"action_type": "unlock", "asset_id": "low-confidence-second"}]
    assert events[0]["details"]["prior_support_enabled"] is False
    assert events[0]["details"]["reveal_policy"] == "gate-only"
    assert events[0]["details"]["recommendation_support"] == 0.0
    assert events[0]["details"]["ordering"]["expected_technique_gain"] == 0.9


def test_prior_influence_compares_reveal_actions_not_only_opened_assets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        reveal_policy_module,
        "_evaluate_policy_actions",
        lambda **_kwargs: (
            ["same-asset"],
            [{"action_type": "unlock", "asset_id": "same-asset"}],
            [{"details": {"prior_degraded": None}}],
        ),
    )
    monkeypatch.setattr(
        reveal_policy_module,
        "gate_only_reveals",
        lambda *_args, **_kwargs: (
            ["same-asset"],
            [
                {
                    "action_type": "configure",
                    "asset_id": "same-asset",
                    "configuration_id": "variant-a",
                }
            ],
            [],
        ),
    )

    row = evaluate_scenario(
        {"scenario_id": "same-asset-different-action"},
        assets=[],
        catalog_path=tmp_path / "catalog.json",
        prior_path=tmp_path / "prior.json",
        policy="controller",
        config=reveal_policy_module.RuntimeConfig(),
    )

    assert row["prior_influenced"] is True
    assert row["prior_comparison_step_count"] == 1


def test_prior_influence_excludes_degraded_prior_steps(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        reveal_policy_module,
        "_evaluate_policy_actions",
        lambda **_kwargs: (
            ["controller-choice"],
            [{"action_type": "unlock", "asset_id": "controller-choice"}],
            [{"details": {"prior_degraded": "prior file missing"}}],
        ),
    )
    monkeypatch.setattr(
        reveal_policy_module,
        "gate_only_reveals",
        lambda *_args, **_kwargs: (
            ["gate-choice"],
            [{"action_type": "unlock", "asset_id": "gate-choice"}],
            [],
        ),
    )

    row = evaluate_scenario(
        {"scenario_id": "degraded-prior"},
        assets=[],
        catalog_path=tmp_path / "catalog.json",
        prior_path=tmp_path / "prior.json",
        policy="controller",
        config=reveal_policy_module.RuntimeConfig(),
    )

    assert row["prior_influenced"] is False
    assert row["prior_comparison_step_count"] == 0


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
                        "expected_reveals": [
                            {"action_type": "unlock", "asset_id": "finance-share"}
                        ],
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
                        "expected_reveals": [
                            {"action_type": "unlock", "asset_id": "finance-share"}
                        ],
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
    controller = report["policies"]["controller"]
    assert controller["reveal_correctness"] == 1.0
    assert controller["decision_trace_completeness_rate"] == 1.0
    assert controller["correct_no_reveal_rate"] == 1.0
    assert controller["unlock_reveal_count"] == 2
    assert controller["configuration_reveal_count"] == 0
    assert controller["unexpected_reveal_count"] == 0
    assert controller["strict_expected_reveal_match_rate"] == 1.0
    assert "prior_influence_rate" in controller
    assert "prior_influenced_step_count" in controller
    assert controller["prior_comparison_step_count"] == controller["step_count"]
    assert report["policies"]["gate-only"]["prior_comparison_step_count"] == 0
    assert report["policies"]["all-open"]["prior_comparison_step_count"] == 0
    assert "diagnostic_or_useful_per_reveal" in controller
    assert controller["gate_decision_point_count"] > 0
    assert controller["gate_reveal_decision_space_avg"] >= controller["gate_eligible_reveal_options_avg"]
    assert "gate_eligible_reveal_options_avg" in controller
    assert "gate_eligible_assets_after_gate_avg" not in controller
    assert "gate_eligible_configuration_options_avg" not in controller
    assert 0 <= controller["gate_narrowing_rate"] <= 1
    assert sum(controller["gate_eligible_bucket_counts"].values()) == controller["gate_decision_point_count"]
    assert controller["rejection_reason_counts"]
    assert controller["prior_influenced_scenario_count"] >= 0
    assert report["policies"]["passive"]["avg_opened_assets"] == 0
    assert report["policies"]["top-recommendation"]["reveal_correctness"] == 1.0
    assert report["policies"]["random-eligible"]["scenario_count"] == 3
    assert report["policies"]["all-open"]["hidden_violation_rate"] > 0
    assert report["policies"]["all-open"]["irrelevant_reveal_rate"] > 0
    assert report["policies"]["all-open"]["unexpected_reveal_count"] > 0
    summary = format_reveal_policy_report_summary([("Fixture scenarios", report)])
    assert "Gate narrowing and candidate-space shape" in summary
    assert "Prior influence" in summary
    assert "Rejection reason distribution" in summary
    assert "Trace/audit checks" in summary
    assert "Fixture scenarios" in summary

    chart_path = tmp_path / "policy.png"
    write_reveal_policy_chart(report, chart_path)


def test_reveal_policy_loader_skips_comments(tmp_path: Path) -> None:
    scenarios = tmp_path / "scenarios.jsonl"
    scenarios.write_text('# comment\n{"scenario_id": "s1"}\n\n', encoding="utf-8")

    assert load_scenarios(scenarios) == [{"scenario_id": "s1"}]


def test_reveal_policy_timeline_loader_loads_steps() -> None:
    scenario = {
        "scenario_id": "timeline-case",
        "timeline": [
            {"step_id": "public-probe", "new_evidence": [{"evidence_id": "e1"}]},
            {"step_id": "follow-up", "new_evidence": [{"evidence_id": "e2"}]},
        ],
    }

    steps = scenario_timeline(scenario)

    assert [step["step_id"] for step in steps] == ["public-probe", "follow-up"]


def test_reveal_policy_timeline_replays_cumulative_profile_and_unlocked_assets(tmp_path: Path) -> None:
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
                        "unlock_signals": {"any_techniques": ["T1046"]},
                        "selection_profile": {
                            "asset_group": "portal",
                            "covered_techniques": ["T1046"],
                            "telemetry_value": 0.6,
                        },
                    },
                },
                {
                    "asset_id": "finance-share",
                    "asset_name": "Finance Share",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Collection"],
                    "dependencies": ["internal-portal"],
                    "default_settings": {
                        "unlock_signals": {"any_techniques": ["T1005"]},
                        "selection_profile": {
                            "asset_group": "data-share",
                            "covered_techniques": ["T1005"],
                            "telemetry_value": 0.9,
                        },
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
                    {"group_id": "G1", "name": "Fixture", "techniques": ["T1046", "T1005"]},
                    {"group_id": "G2", "name": "Fixture 2", "techniques": ["T1046", "T1005"]},
                    {"group_id": "G3", "name": "Fixture 3", "techniques": ["T1046", "T1005"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    scenarios = tmp_path / "scenarios.json"
    scenarios.write_text(
        json.dumps(
            [
                {
                    "scenario_id": "timeline-replay",
                    "expected_reasonable_assets": ["internal-portal", "finance-share"],
                    "expected_hidden_assets": [],
                    "useful_followup_assets": ["internal-portal", "finance-share"],
                    "timeline": [
                        {
                            "step_id": "public-discovery",
                            "phase": "public entrypoint",
                            "new_evidence": [
                                {
                                    "evidence_id": "e1",
                                    "technique": "T1046",
                                    "tactic": "Discovery",
                                    "weight": 0.9,
                                }
                            ],
                            "expected_reveals": [
                                {"action_type": "unlock", "asset_id": "internal-portal"}
                            ],
                            "source_refs": [
                                {"reference_id": "fixture", "exactness_level": "technique-level"}
                            ],
                        },
                        {
                            "step_id": "internal-collection",
                            "phase": "follow-up",
                            "new_evidence": [
                                {
                                    "evidence_id": "e2",
                                    "asset_id": "internal-portal",
                                    "technique": "T1005",
                                    "tactic": "Collection",
                                    "weight": 0.9,
                                }
                            ],
                            "expected_reveals": [
                                {"action_type": "unlock", "asset_id": "finance-share"}
                            ],
                            "touched_assets": ["internal-portal"],
                            "source_refs": [
                                {"reference_id": "fixture", "exactness_level": "technique-level"}
                            ],
                        },
                        {
                            "step_id": "wait",
                            "phase": "response gate",
                            "new_evidence": [],
                            "expected_no_reveal": True,
                            "expected_response_gate_wait": True,
                            "source_refs": [
                                {"reference_id": "fixture", "exactness_level": "negative-control"}
                            ],
                        },
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )

    report = evaluate_reveal_policies(
        scenario_file=scenarios,
        catalog_path=catalog,
        prior_path=prior,
        policies=("all-open",),
        replay_mode="sequence",
    )

    row = report["policies"]["all-open"]["rows"][0]
    assert row["opened_assets"] == ["internal-portal", "finance-share"]
    assert [step["opened_assets"] for step in row["timeline"]] == [
        ["internal-portal"],
        ["finance-share"],
        [],
    ]
    assert row["step_count"] == 3
    assert row["step_no_reveal_correctness_rate"] == 1.0
    assert row["response_gate_wait_correct_count"] == 1
    assert row["source_traceability_status"] == "declared"
    assert report["policies"]["all-open"]["source_traceability_declared_rate"] == 1.0


def test_reveal_policy_sequence_scores_anchor_steps(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps(
            [
                {
                    "asset_id": "entry",
                    "asset_name": "Entry",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Discovery"],
                    "dependencies": [],
                    "default_settings": {"selection_profile": {"covered_techniques": ["T1046"]}},
                },
                {
                    "asset_id": "followup",
                    "asset_name": "Followup",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Collection"],
                    "dependencies": ["entry"],
                    "default_settings": {"selection_profile": {"covered_techniques": ["T1005"]}},
                },
                {
                    "asset_id": "hidden",
                    "asset_name": "Hidden",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Discovery"],
                    "dependencies": [],
                    "default_settings": {"selection_profile": {"covered_techniques": ["T1046"]}},
                },
            ]
        ),
        encoding="utf-8",
    )
    prior = tmp_path / "prior.json"
    prior.write_text(
        json.dumps({"schema_version": "v1", "method": "attack_group_collaborative_filtering", "groups": []}),
        encoding="utf-8",
    )
    scenarios = tmp_path / "scenarios.json"
    scenarios.write_text(
        json.dumps(
            [
                {
                    "scenario_id": "anchor-ok",
                    "expected_reasonable_assets": ["entry", "followup"],
                    "expected_hidden_assets": [],
                    "timeline": [
                        {
                            "step_id": "buildup",
                            "new_evidence": [{"evidence_id": "e1", "technique": "T1046"}],
                            "source_refs": [{"reference_id": "fixture", "exactness_level": "technique-level"}],
                        },
                        {
                            "step_id": "anchor-followup",
                            "anchor_check": True,
                            "new_evidence": [{"evidence_id": "e2", "technique": "T1005"}],
                            "expected_reveals": [{"action_type": "unlock", "asset_id": "followup"}],
                            "source_refs": [{"reference_id": "fixture", "exactness_level": "technique-level"}],
                        },
                    ],
                },
                {
                    "scenario_id": "anchor-missing",
                    "expected_reasonable_assets": ["entry"],
                    "expected_hidden_assets": [],
                    "timeline": [
                        {
                            "step_id": "bad-anchor",
                            "anchor_check": True,
                            "new_evidence": [{"evidence_id": "e3", "technique": "T1046"}],
                            "expected_reveals": [{"action_type": "unlock", "asset_id": "followup"}],
                            "source_refs": [{"reference_id": "fixture", "exactness_level": "technique-level"}],
                        }
                    ],
                },
                {
                    "scenario_id": "anchor-no-reveal-fail",
                    "expected_reasonable_assets": ["entry"],
                    "expected_hidden_assets": [],
                    "timeline": [
                        {
                            "step_id": "should-wait",
                            "anchor_check": True,
                            "expected_no_reveal": True,
                            "new_evidence": [{"evidence_id": "e4", "technique": "T1046"}],
                            "source_refs": [{"reference_id": "fixture", "exactness_level": "negative-control"}],
                        }
                    ],
                },
                {
                    "scenario_id": "hidden-opened",
                    "expected_reasonable_assets": ["entry"],
                    "expected_hidden_assets": ["hidden"],
                    "timeline": [
                        {
                            "step_id": "hidden",
                            "new_evidence": [{"evidence_id": "e5", "technique": "T1046"}],
                            "source_refs": [{"reference_id": "fixture", "exactness_level": "technique-level"}],
                        }
                    ],
                },
                {
                    "scenario_id": "anchor-unscored",
                    "expected_reasonable_assets": ["entry"],
                    "expected_hidden_assets": [],
                    "timeline": [
                        {
                            "step_id": "unconstrained-anchor",
                            "anchor_check": True,
                            "new_evidence": [{"evidence_id": "e6", "technique": "T1046"}],
                            "source_refs": [{"reference_id": "fixture", "exactness_level": "technique-level"}],
                        }
                    ],
                },
            ]
        ),
        encoding="utf-8",
    )

    report = evaluate_reveal_policies(
        scenario_file=scenarios,
        catalog_path=catalog,
        prior_path=prior,
        policies=("all-open",),
        replay_mode="sequence",
    )

    rows = {row["scenario_id"]: row for row in report["policies"]["all-open"]["rows"]}
    assert rows["anchor-ok"]["anchor_step_correctness_rate"] == 1.0
    assert rows["anchor-missing"]["anchor_missing_expected_reveals"]
    assert rows["anchor-no-reveal-fail"]["anchor_failed_no_reveal_count"] == 1
    assert rows["anchor-unscored"]["anchor_step_count"] == 1
    assert rows["anchor-unscored"]["anchor_step_correct_count"] == 0
    assert rows["hidden-opened"]["hidden_violations"] == ["hidden"]
    aggregate = report["policies"]["all-open"]
    assert aggregate["anchor_step_count"] == 4
    assert aggregate["anchor_missing_expected_reveal_count"] == 1
    assert aggregate["anchor_failed_no_reveal_count"] == 1


def test_reveal_policy_reports_trace_level_choice_signals(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps(
            [
                {
                    "asset_id": "asset-main",
                    "asset_name": "Credential Cache",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Credential Access"],
                    "dependencies": [],
                    "default_settings": {
                        "selection_profile": {
                            "asset_group": "credential-store",
                            "covered_techniques": ["T1552.001"],
                            "optional_dependency_signals": {
                                "any_http_indicators": ["path:/credential"],
                                "any_techniques": ["T1552.001"],
                            },
                            "telemetry_value": 0.8,
                        }
                    },
                },
                {
                    "asset_id": "asset-explore",
                    "asset_name": "Discovery Portal",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Discovery"],
                    "dependencies": [],
                    "default_settings": {
                        "selection_profile": {
                            "asset_group": "portal",
                            "covered_techniques": ["T1046"],
                            "optional_dependency_signals": {
                                "any_http_indicators": ["path:/discovery"],
                                "any_techniques": ["T1046"],
                            },
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
                "groups": [],
            }
        ),
        encoding="utf-8",
    )
    scenarios = tmp_path / "scenarios.json"
    base_scenario = {
        "initial_unlocked_assets": [],
            "profile": {
                "conf_by_technique": {"T1552.001": 0.6, "T1046": 0.7},
                "recent_techniques": ["T1552.001", "T1046"],
                "recent_public_http_indicators": ["path:/credential", "path:/discovery"],
                "recent_evidence_ids": ["e-choice"],
            },
        "expected_reasonable_assets": ["asset-main", "asset-explore"],
        "expected_hidden_assets": [],
        "useful_followup_assets": ["asset-main", "asset-explore"],
        "expected_reveals": [
            {"action_type": "unlock", "asset_id": "asset-main"},
            {"action_type": "unlock", "asset_id": "asset-explore"},
        ],
    }
    scenarios.write_text(
        json.dumps(
            [
                {**base_scenario, "scenario_id": "main-touch", "touched_assets": ["asset-main"]},
                {**base_scenario, "scenario_id": "explore-touch", "touched_assets": ["asset-explore"]},
                {**base_scenario, "scenario_id": "both-touch", "touched_assets": ["asset-main", "asset-explore"]},
                {**base_scenario, "scenario_id": "neither-touch", "touched_assets": []},
            ]
        ),
        encoding="utf-8",
    )

    report = evaluate_reveal_policies(
        scenario_file=scenarios,
        catalog_path=catalog,
        prior_path=prior,
        policies=("controller",),
    )

    rows = {row["scenario_id"]: row for row in report["policies"]["controller"]["rows"]}
    assert rows["main-touch"]["choice_signal"] == "preferred_main"
    assert rows["explore-touch"]["choice_signal"] == "preferred_explore"
    assert rows["both-touch"]["choice_signal"] == "mixed"
    assert rows["neither-touch"]["choice_signal"] == "unresolved"
    assert rows["main-touch"]["main_reveal_assets"] == ["asset-main"]
    assert rows["main-touch"]["explore_reveal_assets"] == ["asset-explore"]
    assert rows["main-touch"]["touched_reveal_assets"] == ["asset-main"]
    aggregate = report["policies"]["controller"]
    assert aggregate["choice_signal_eligible_count"] == 4
    assert aggregate["choice_signal_count"] == 3
    assert aggregate["resolved_choice_rate"] == 0.75
    assert aggregate["choice_signal_counts"] == {
        "preferred_main": 1,
        "preferred_explore": 1,
        "mixed": 1,
        "unresolved": 1,
    }
