from __future__ import annotations

import json

import pytest

from scripts.runtime import adaptive_controller_loop


pytestmark = pytest.mark.unit


def test_tick_once_applies_unlock_and_writes_decision_trace(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    (state_dir / "bindings.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "attacker_key": "198.51.100.10",
                        "binding_id": "binding-1",
                        "unlocked_assets": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "profiles.json").write_text(
        json.dumps(
            {
                "profiles": {
                    "198.51.100.10": {
                        "attacker_key": "198.51.100.10",
                        "recent_tactics": ["Credential Access"],
                        "recent_techniques": ["T1110"],
                        "recent_evidence_ids": ["e-1"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    def fake_post_json(url, payload, timeout_seconds):
        if url.endswith("/v1/controller/tick"):
            return {
                "candidate_asset_ids": ["internal-portal"],
                "actions": [
                    {
                        "action_type": "unlock",
                        "binding_id": "binding-1",
                        "asset_id": "internal-portal",
                        "reason": "exploit score",
                    }
                ],
                "decision_events": [
                    {
                        "reason": "exploit selected internal-portal",
                    }
                ],
            }
        return {
            "binding": {
                "binding_id": "binding-1",
                "unlocked_assets": ["internal-portal"],
            },
            "route_updates": ["binding binding-1 exposes internal-portal"],
            "runtime_events": [
                {
                    "asset_id": "internal-portal",
                    "asset_name": "Internal Portal",
                    "status": "running",
                    "template_family": "web-honeypot",
                    "settings": {
                        "runtime_backend": "docker",
                        "image": "nginx:alpine",
                        "port_mappings": [
                            {
                                "host": "127.0.0.1",
                                "host_port": 18080,
                                "container_port": 80,
                            }
                        ],
                    },
                }
            ],
        }

    monkeypatch.setattr(adaptive_controller_loop, "post_json", fake_post_json)
    trace_file = state_dir / "decision_trace.json"

    applied = adaptive_controller_loop.tick_once(
        state_dir=state_dir,
        controller_url="http://controller",
        orchestrator_url="http://orchestrator",
        timeout_seconds=0.1,
        trace_file=trace_file,
    )

    assert applied == 1
    trace = json.loads(trace_file.read_text(encoding="utf-8"))
    assert trace["records"][0]["recent_tactics"] == ["Credential Access"]
    assert trace["records"][0]["candidate_asset_ids"] == ["internal-portal"]
    assert trace["records"][0]["route_updates"] == [
        "binding binding-1 exposes internal-portal"
    ]
    assert trace["records"][0]["runtime_events"][0]["port_mappings"] == [
        {"host": "127.0.0.1", "host_port": 18080, "container_port": 80}
    ]


def test_tick_once_applies_configuration_reveal(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    (state_dir / "bindings.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "attacker_key": "198.51.100.11",
                        "binding_id": "binding-2",
                        "unlocked_assets": ["git-internal"],
                        "revealed_configurations": {},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "profiles.json").write_text(
        json.dumps(
            {
                "profiles": {
                    "198.51.100.11": {
                        "attacker_key": "198.51.100.11",
                        "recent_techniques": ["T1213"],
                        "recent_evidence_ids": ["e-config"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    controller_payloads = []

    def fake_post_json(url, payload, timeout_seconds):
        if url.endswith("/v1/controller/tick"):
            controller_payloads.append(payload)
            return {
                "candidate_asset_ids": ["git-internal"],
                "actions": [
                    {
                        "action_type": "configure",
                        "binding_id": "binding-2",
                        "asset_id": "git-internal",
                        "configuration_id": "git-db-credential-clue",
                        "configuration": {"kind": "content"},
                        "reason": "configure git",
                    }
                ],
                "decision_events": [
                    {
                        "asset_added": "git-internal",
                        "details": {
                            "selected_technique": "T1213",
                            "matched_dependency_markers": ["any_techniques:T1213"],
                            "asset_group": "developer",
                        },
                    }
                ],
            }
        return {
            "binding": {
                "binding_id": "binding-2",
                "unlocked_assets": ["git-internal"],
                "revealed_configurations": {
                    "git-internal": ["git-db-credential-clue"]
                },
            },
            "route_updates": [
                "binding binding-2 configures git-internal:git-db-credential-clue"
            ],
            "runtime_events": [],
        }

    monkeypatch.setattr(adaptive_controller_loop, "post_json", fake_post_json)
    trace_file = state_dir / "decision_trace.json"

    applied = adaptive_controller_loop.tick_once(
        state_dir=state_dir,
        controller_url="http://controller",
        orchestrator_url="http://orchestrator",
        timeout_seconds=0.1,
        trace_file=trace_file,
    )

    assert applied == 1
    assert controller_payloads[0]["revealed_configurations"] == {}
    trace = json.loads(trace_file.read_text(encoding="utf-8"))
    assert trace["records"][0]["revealed_configurations_after"] == {
        "git-internal": ["git-db-credential-clue"]
    }


def test_tick_once_processes_new_evidence_once_and_limits_unlock_actions(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    (state_dir / "bindings.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "attacker_key": "198.51.100.10",
                        "binding_id": "binding-1",
                        "unlocked_assets": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "profiles.json").write_text(
        json.dumps(
            {
                "profiles": {
                    "198.51.100.10": {
                        "attacker_key": "198.51.100.10",
                        "recent_tactics": ["Credential Access"],
                        "recent_techniques": ["T1110"],
                        "recent_evidence_ids": ["e-1"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    applied_payloads = []

    def fake_post_json(url, payload, timeout_seconds):
        if url.endswith("/v1/controller/tick"):
            return {
                "candidate_asset_ids": ["internal-portal", "finance-share"],
                "actions": [
                    {
                        "action_type": "unlock",
                        "binding_id": "binding-1",
                        "asset_id": "internal-portal",
                        "reason": "first",
                    },
                    {
                        "action_type": "unlock",
                        "binding_id": "binding-1",
                        "asset_id": "finance-share",
                        "reason": "second",
                    },
                ],
                "decision_events": [],
            }

        applied_payloads.append(payload)
        return {
            "binding": {
                "binding_id": "binding-1",
                "unlocked_assets": ["internal-portal"],
            },
            "route_updates": ["binding binding-1 exposes internal-portal"],
            "runtime_events": [],
        }

    monkeypatch.setattr(adaptive_controller_loop, "post_json", fake_post_json)
    loop_state_file = state_dir / "adaptive_loop_state.json"
    trace_file = state_dir / "decision_trace.json"

    first_applied = adaptive_controller_loop.tick_once(
        state_dir=state_dir,
        controller_url="http://controller",
        orchestrator_url="http://orchestrator",
        timeout_seconds=0.1,
        trace_file=trace_file,
        loop_state_file=loop_state_file,
        max_actions_per_trigger=1,
    )
    second_applied = adaptive_controller_loop.tick_once(
        state_dir=state_dir,
        controller_url="http://controller",
        orchestrator_url="http://orchestrator",
        timeout_seconds=0.1,
        trace_file=trace_file,
        loop_state_file=loop_state_file,
        max_actions_per_trigger=1,
    )

    assert first_applied == 1
    assert second_applied == 0
    assert len(applied_payloads) == 1
    assert applied_payloads[0]["actions"] == [
        {
            "action_type": "unlock",
            "binding_id": "binding-1",
            "asset_id": "internal-portal",
            "reason": "first",
        }
    ]

    state = json.loads(loop_state_file.read_text(encoding="utf-8"))
    assert state["processed_evidence_ids_by_attacker"] == {
        "198.51.100.10": ["e-1"]
    }

    trace = json.loads(trace_file.read_text(encoding="utf-8"))
    assert trace["records"][0]["actions"][0]["asset_id"] == "internal-portal"
    assert trace["records"][0]["dropped_actions"][0]["asset_id"] == "finance-share"


def test_tick_once_writes_no_reveal_decision_trace(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    (state_dir / "bindings.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "attacker_key": "198.51.100.20",
                        "binding_id": "binding-no-reveal",
                        "unlocked_assets": ["internal-portal"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "profiles.json").write_text(
        json.dumps(
            {
                "profiles": {
                    "198.51.100.20": {
                        "attacker_key": "198.51.100.20",
                        "recent_tactics": ["Discovery"],
                        "recent_techniques": ["T1046"],
                        "recent_evidence_ids": ["e-no-reveal"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    def fake_post_json(url, payload, timeout_seconds):
        if url.endswith("/v1/controller/tick"):
            return {
                "candidate_asset_ids": [],
                "actions": [],
                "decision_events": [
                    {
                        "reason": "no reveal",
                        "details": {
                            "reveal_action": "no_reveal",
                            "no_reveal_reason": "scanner-like traffic",
                        },
                    }
                ],
            }
        raise AssertionError("orchestrator should not be called for no-reveal")

    monkeypatch.setattr(adaptive_controller_loop, "post_json", fake_post_json)
    loop_state_file = state_dir / "adaptive_loop_state.json"
    trace_file = state_dir / "decision_trace.json"

    applied = adaptive_controller_loop.tick_once(
        state_dir=state_dir,
        controller_url="http://controller",
        orchestrator_url="http://orchestrator",
        timeout_seconds=0.1,
        trace_file=trace_file,
        loop_state_file=loop_state_file,
    )

    assert applied == 0
    trace = json.loads(trace_file.read_text(encoding="utf-8"))
    assert trace["records"][0]["actions"] == []
    assert trace["records"][0]["route_updates"] == []
    assert trace["records"][0]["decision_events"][0]["reason"] == "no reveal"

    state = json.loads(loop_state_file.read_text(encoding="utf-8"))
    assert state["processed_evidence_ids_by_attacker"] == {
        "198.51.100.20": ["e-no-reveal"]
    }


def test_reveal_feedback_records_reveal_and_later_useful_touch(tmp_path) -> None:
    feedback_file = tmp_path / "reveal_feedback.json"
    evidence_file = tmp_path / "evidence.json"

    adaptive_controller_loop.record_reveal_feedback(
        feedback_file=feedback_file,
        attacker_key="198.51.100.10",
        binding_id="binding-1",
        applied_actions=[
            {
                "action_type": "unlock",
                "binding_id": "binding-1",
                "asset_id": "finance-share",
                "reason": "selected",
            }
        ],
        controller_response={
            "candidate_asset_ids": ["internal-portal", "finance-share", "git-internal"],
            "decision_events": [
                {
                    "asset_added": "finance-share",
                    "details": {
                        "selected_technique": "T1552.001",
                        "matched_dependency_markers": ["any_http_indicators:path:.bak"],
                        "asset_group": "data-share",
                    },
                }
            ],
        },
    )
    evidence_file.write_text(
        json.dumps(
            {
                "records": {
                    "198.51.100.10": [
                        {
                            "attacker_key": "198.51.100.10",
                            "ts": "2099-01-01T00:00:01Z",
                            "tech_id": "T1005",
                            "source_ref": {
                                "source": "internal_http",
                                "asset_id": "finance-share",
                                "http_path": "/finance/archive/2024/payroll-archive.zip",
                            },
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    adaptive_controller_loop.update_reveal_feedback_from_evidence(
        feedback_file=feedback_file,
        evidence_file=evidence_file,
        feedback_window_seconds=300,
    )

    payload = json.loads(feedback_file.read_text(encoding="utf-8"))
    group = payload["contexts"]["T1552.001|any_http_indicators:path:.bak"]["asset_groups"]["data-share"]
    assert group["revealed"] == 1
    assert group["useful"] == 1
    assert payload["pending"][0]["status"] == "useful"
    assert payload["pending"][0]["available_assets"] == [
        "internal-portal",
        "finance-share",
        "git-internal",
    ]
    assert payload["pending"][0]["revealed_assets"] == ["finance-share"]


def test_reveal_feedback_marks_unclassified_touch_as_shallow(tmp_path) -> None:
    feedback_file = tmp_path / "reveal_feedback.json"
    evidence_file = tmp_path / "evidence.json"

    adaptive_controller_loop.record_reveal_feedback(
        feedback_file=feedback_file,
        attacker_key="198.51.100.20",
        binding_id="binding-2",
        applied_actions=[
            {
                "action_type": "unlock",
                "binding_id": "binding-2",
                "asset_id": "internal-portal",
                "reason": "selected",
            }
        ],
        controller_response={
            "candidate_asset_ids": ["internal-portal"],
            "decision_events": [
                {
                    "asset_added": "internal-portal",
                    "details": {
                        "selected_technique": "T1046",
                        "matched_dependency_markers": [],
                        "asset_group": "portal",
                    },
                }
            ],
        },
    )
    evidence_file.write_text(
        json.dumps(
            {
                "records": {
                    "198.51.100.20": [
                        {
                            "attacker_key": "198.51.100.20",
                            "ts": "2099-01-01T00:00:01Z",
                            "source_ref": {
                                "source": "internal_http",
                                "asset_id": "internal-portal",
                                "http_path": "/",
                            },
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    adaptive_controller_loop.update_reveal_feedback_from_evidence(
        feedback_file=feedback_file,
        evidence_file=evidence_file,
        feedback_window_seconds=300,
    )

    payload = json.loads(feedback_file.read_text(encoding="utf-8"))
    group = payload["contexts"]["T1046"]["asset_groups"]["portal"]
    assert group["revealed"] == 1
    assert group["shallow"] == 1
    assert payload["pending"][0]["status"] == "shallow"


def test_reveal_feedback_marks_expired_reveal_as_ignored(tmp_path) -> None:
    feedback_file = tmp_path / "reveal_feedback.json"
    evidence_file = tmp_path / "evidence.json"

    adaptive_controller_loop.record_reveal_feedback(
        feedback_file=feedback_file,
        attacker_key="198.51.100.30",
        binding_id="binding-3",
        applied_actions=[
            {
                "action_type": "unlock",
                "binding_id": "binding-3",
                "asset_id": "git-internal",
                "reason": "selected",
            }
        ],
        controller_response={
            "candidate_asset_ids": ["internal-portal", "git-internal"],
            "decision_events": [
                {
                    "asset_added": "git-internal",
                    "details": {
                        "selected_technique": "T1083",
                        "matched_dependency_markers": ["any_http_paths:/assets/app.js.map"],
                        "asset_group": "developer",
                    },
                }
            ],
        },
    )
    payload = json.loads(feedback_file.read_text(encoding="utf-8"))
    payload["pending"][0]["ts"] = "2000-01-01T00:00:00Z"
    feedback_file.write_text(json.dumps(payload), encoding="utf-8")
    evidence_file.write_text(json.dumps({"records": {}}), encoding="utf-8")

    adaptive_controller_loop.update_reveal_feedback_from_evidence(
        feedback_file=feedback_file,
        evidence_file=evidence_file,
        feedback_window_seconds=300,
    )

    payload = json.loads(feedback_file.read_text(encoding="utf-8"))
    group = payload["contexts"]["T1083|any_http_paths:/assets/app.js.map"]["asset_groups"]["developer"]
    assert group["revealed"] == 1
    assert group["ignored"] == 1
    assert payload["pending"][0]["status"] == "ignored"
