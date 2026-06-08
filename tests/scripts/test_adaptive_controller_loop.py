from __future__ import annotations

import json

import pytest

from scripts.runtime import adaptive_controller_loop


pytestmark = pytest.mark.unit


def _write_runtime_state(
    state_dir,
    *,
    attacker_key: str = "198.51.100.50",
    binding_id: str = "binding-gate",
    evidence_id: str = "e-gate",
    profile_extra: dict | None = None,
) -> None:
    state_dir.mkdir()
    (state_dir / "bindings.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "attacker_key": attacker_key,
                        "binding_id": binding_id,
                        "unlocked_assets": ["internal-portal"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    profile = {
        "attacker_key": attacker_key,
        "recent_techniques": ["T1046"],
        "recent_evidence_ids": [evidence_id],
    }
    if profile_extra:
        profile.update(profile_extra)
    (state_dir / "profiles.json").write_text(
        json.dumps({"profiles": {attacker_key: profile}}),
        encoding="utf-8",
    )


def _write_feedback_rows(feedback_file, rows: list[dict]) -> None:
    feedback_file.write_text(
        json.dumps({"schema_version": "v1", "contexts": {}, "pending": rows}),
        encoding="utf-8",
    )


def _feedback_row(
    *,
    status: str,
    asset_id: str = "internal-portal",
    revealed_assets: list[str] | None = None,
    ts: str = "2099-01-01T00:00:00Z",
) -> dict:
    return {
        "ts": ts,
        "context_key": "T1046",
        "asset_group": "portal",
        "binding_id": "binding-gate",
        "attacker_key": "198.51.100.50",
        "asset_id": asset_id,
        "available_assets": ["internal-portal", "web-admin-console"],
        "revealed_assets": revealed_assets or [asset_id],
        "status": status,
    }


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
                        "configuration_id": "git-seeded-repository-backend",
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
                    "git-internal": ["git-seeded-repository-backend"]
                },
            },
            "route_updates": [
                "binding binding-2 configures git-internal:git-seeded-repository-backend"
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
        "git-internal": ["git-seeded-repository-backend"]
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


def test_tick_once_applies_main_and_explore_by_default(
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
                        "attacker_key": "198.51.100.11",
                        "binding_id": "binding-main-explore",
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
                    "198.51.100.11": {
                        "attacker_key": "198.51.100.11",
                        "recent_tactics": ["Credential Access", "Discovery"],
                        "recent_techniques": ["T1110", "T1046"],
                        "recent_evidence_ids": ["e-main-explore"],
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
                        "binding_id": "binding-main-explore",
                        "asset_id": "internal-portal",
                        "reason": "main",
                    },
                    {
                        "action_type": "unlock",
                        "binding_id": "binding-main-explore",
                        "asset_id": "finance-share",
                        "reason": "explore",
                    },
                ],
                "decision_events": [],
            }

        applied_payloads.append(payload)
        return {
            "binding": {
                "binding_id": "binding-main-explore",
                "unlocked_assets": ["internal-portal", "finance-share"],
            },
            "route_updates": [
                "binding binding-main-explore exposes internal-portal",
                "binding binding-main-explore exposes finance-share",
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

    assert applied == 2
    assert applied_payloads[0]["actions"] == [
        {
            "action_type": "unlock",
            "binding_id": "binding-main-explore",
            "asset_id": "internal-portal",
            "reason": "main",
        },
        {
            "action_type": "unlock",
            "binding_id": "binding-main-explore",
            "asset_id": "finance-share",
            "reason": "explore",
        },
    ]
    trace = json.loads(trace_file.read_text(encoding="utf-8"))
    assert trace["records"][0]["dropped_actions"] == []


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


def test_response_gate_blocks_pending_reveal_without_touch(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "runtime"
    _write_runtime_state(state_dir)
    feedback_file = state_dir / "reveal_feedback.json"
    _write_feedback_rows(feedback_file, [_feedback_row(status="pending")])

    def fake_post_json(url, payload, timeout_seconds):
        raise AssertionError("controller and orchestrator should be gated")

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
        feedback_file=feedback_file,
    )

    assert applied == 0
    trace = json.loads(trace_file.read_text(encoding="utf-8"))
    details = trace["records"][0]["decision_events"][0]["details"]
    assert details["no_reveal_reason"] == "waiting_for_reveal_response"
    assert details["response_gate"]["revealed_assets"] == ["internal-portal"]

    state = json.loads(loop_state_file.read_text(encoding="utf-8"))
    assert state["processed_evidence_ids_by_attacker"] == {
        "198.51.100.50": ["e-gate"]
    }


@pytest.mark.parametrize("status", ["useful", "shallow"])
def test_response_gate_allows_resolved_reveal_status(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    state_dir = tmp_path / "runtime"
    _write_runtime_state(state_dir)
    feedback_file = state_dir / "reveal_feedback.json"
    _write_feedback_rows(feedback_file, [_feedback_row(status=status)])
    calls: list[str] = []

    def fake_post_json(url, payload, timeout_seconds):
        if url.endswith("/v1/controller/tick"):
            calls.append("controller")
            return {"candidate_asset_ids": [], "actions": [], "decision_events": []}
        raise AssertionError("orchestrator should not be called for no-reveal")

    monkeypatch.setattr(adaptive_controller_loop, "post_json", fake_post_json)

    applied = adaptive_controller_loop.tick_once(
        state_dir=state_dir,
        controller_url="http://controller",
        orchestrator_url="http://orchestrator",
        timeout_seconds=0.1,
        feedback_file=feedback_file,
    )

    assert applied == 0
    assert calls == ["controller"]


def test_response_gate_blocks_ignored_reveal_without_touch(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "runtime"
    _write_runtime_state(state_dir)
    feedback_file = state_dir / "reveal_feedback.json"
    _write_feedback_rows(feedback_file, [_feedback_row(status="ignored")])

    def fake_post_json(url, payload, timeout_seconds):
        raise AssertionError("controller and orchestrator should be gated")

    monkeypatch.setattr(adaptive_controller_loop, "post_json", fake_post_json)

    applied = adaptive_controller_loop.tick_once(
        state_dir=state_dir,
        controller_url="http://controller",
        orchestrator_url="http://orchestrator",
        timeout_seconds=0.1,
        feedback_file=feedback_file,
    )

    assert applied == 0


def test_response_gate_allows_ignored_reveal_with_recent_asset_touch(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "runtime"
    _write_runtime_state(
        state_dir,
        profile_extra={"recent_asset_ids": ["internal-portal"]},
    )
    feedback_file = state_dir / "reveal_feedback.json"
    _write_feedback_rows(feedback_file, [_feedback_row(status="ignored")])
    calls: list[str] = []

    def fake_post_json(url, payload, timeout_seconds):
        if url.endswith("/v1/controller/tick"):
            calls.append("controller")
            return {"candidate_asset_ids": [], "actions": [], "decision_events": []}
        raise AssertionError("orchestrator should not be called for no-reveal")

    monkeypatch.setattr(adaptive_controller_loop, "post_json", fake_post_json)

    adaptive_controller_loop.tick_once(
        state_dir=state_dir,
        controller_url="http://controller",
        orchestrator_url="http://orchestrator",
        timeout_seconds=0.1,
        feedback_file=feedback_file,
    )

    assert calls == ["controller"]


def test_response_gate_allows_main_explore_batch_when_one_asset_responds(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "runtime"
    _write_runtime_state(state_dir)
    feedback_file = state_dir / "reveal_feedback.json"
    revealed_assets = ["internal-portal", "web-admin-console"]
    _write_feedback_rows(
        feedback_file,
        [
            _feedback_row(
                status="useful",
                asset_id="internal-portal",
                revealed_assets=revealed_assets,
            ),
            _feedback_row(
                status="pending",
                asset_id="web-admin-console",
                revealed_assets=revealed_assets,
            ),
        ],
    )
    calls: list[str] = []

    def fake_post_json(url, payload, timeout_seconds):
        if url.endswith("/v1/controller/tick"):
            calls.append("controller")
            return {"candidate_asset_ids": [], "actions": [], "decision_events": []}
        raise AssertionError("orchestrator should not be called for no-reveal")

    monkeypatch.setattr(adaptive_controller_loop, "post_json", fake_post_json)

    adaptive_controller_loop.tick_once(
        state_dir=state_dir,
        controller_url="http://controller",
        orchestrator_url="http://orchestrator",
        timeout_seconds=0.1,
        feedback_file=feedback_file,
    )

    assert calls == ["controller"]


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


def test_reveal_feedback_does_not_block_after_configuration_only(tmp_path) -> None:
    feedback_file = tmp_path / "reveal_feedback.json"

    adaptive_controller_loop.record_reveal_feedback(
        feedback_file=feedback_file,
        attacker_key="198.51.100.15",
        binding_id="binding-config",
        applied_actions=[
            {
                "action_type": "configure",
                "binding_id": "binding-config",
                "asset_id": "malware-sink",
                "configuration_id": "malware-dionaea-same-port-upgrade",
                "target_asset_id": "dionaea-capture",
                "reason": "selected",
            }
        ],
        controller_response={
            "candidate_asset_ids": ["malware-sink", "dionaea-capture"],
            "decision_events": [
                {
                    "asset_added": "dionaea-capture",
                    "details": {
                        "selected_technique": "T1105",
                        "matched_dependency_markers": ["any_techniques:T1105"],
                        "asset_group": "payload-transfer-high",
                    },
                }
            ],
        },
    )

    assert not feedback_file.exists()
    assert adaptive_controller_loop.response_gate_decision(
        feedback_file=feedback_file,
        attacker_key="198.51.100.15",
        binding_id="binding-config",
        profile={},
    )["allowed"] is True


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


def test_reveal_feedback_marks_raw_internal_http_touch_as_shallow(tmp_path) -> None:
    feedback_file = tmp_path / "reveal_feedback.json"
    evidence_file = tmp_path / "evidence.json"
    internal_http_events_file = tmp_path / "internal_http_events.jsonl"

    adaptive_controller_loop.record_reveal_feedback(
        feedback_file=feedback_file,
        attacker_key="198.51.100.25",
        binding_id="binding-raw-touch",
        applied_actions=[
            {
                "action_type": "unlock",
                "binding_id": "binding-raw-touch",
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
    evidence_file.write_text(json.dumps({"records": {}}), encoding="utf-8")
    internal_http_events_file.write_text(
        json.dumps(
            {
                "attacker_key": "198.51.100.25",
                "asset_id": "internal-portal",
                "method": "GET",
                "path": "/",
                "surface": "internal",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    adaptive_controller_loop.update_reveal_feedback_from_evidence(
        feedback_file=feedback_file,
        evidence_file=evidence_file,
        internal_http_events_file=internal_http_events_file,
        feedback_window_seconds=300,
    )

    payload = json.loads(feedback_file.read_text(encoding="utf-8"))
    group = payload["contexts"]["T1046"]["asset_groups"]["portal"]
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
