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
