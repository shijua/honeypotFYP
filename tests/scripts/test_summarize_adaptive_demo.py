from __future__ import annotations

import json

import pytest

from scripts import summarize_adaptive_demo
from scripts.summarize_adaptive_demo import summarize_demo, write_report


pytestmark = pytest.mark.unit


def test_summarize_demo_groups_behavior_profile_and_opened_ports(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        summarize_adaptive_demo,
        "current_docker_status",
        lambda: summarize_adaptive_demo.DockerStatusProbe(
            statuses={"honeynet-bind-internal-portal": "Up 3 seconds"},
            error=None,
        ),
    )
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    (state_dir / "cowrie_observations.json").write_text(
        json.dumps(
            {
                "observations": [
                    {
                        "attacker_key": "198.51.100.10",
                        "eventid": "cowrie.login.failed",
                    },
                    {
                        "attacker_key": "198.51.100.10",
                        "eventid": "cowrie.command.input",
                        "command": "id",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "bindings.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "attacker_key": "198.51.100.10",
                        "binding_id": "binding-1",
                        "last_seen_ts": "2026-01-01T00:00:00Z",
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
                    "198.51.100.10": {
                        "recent_tactics": ["Credential Access", "Discovery"],
                        "recent_techniques": ["T1110", "T1033"],
                        "conf_by_tactic": {"Credential Access": 0.6},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "asset_runtime.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "binding_id": "binding-1",
                        "asset_id": "internal-portal",
                        "asset_name": "Internal Portal",
                        "status": "running",
                        "template_family": "web-honeypot",
                        "settings": {
                            "container_name": "honeynet-bind-internal-portal",
                            "runtime_backend": "docker",
                            "image": "dtagdevsec/wordpot:24.04.1",
                            "port_mappings": [
                                {
                                    "host": "127.0.0.1",
                                    "host_port": 18080,
                                    "container_port": 80,
                                }
                            ],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "decision_trace.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "attacker_key": "198.51.100.10",
                        "ts": "2026-01-01T00:00:01Z",
                        "recent_tactics": ["Credential Access"],
                        "candidate_asset_ids": ["internal-portal"],
                        "actions": [
                            {
                                "action_type": "unlock",
                                "asset_id": "internal-portal",
                            }
                        ],
                        "decision_events": [
                            {
                                "reason": "exploit selected internal-portal",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    report = summarize_demo(state_dir)

    attacker = report["attackers"][0]
    assert attacker["attacker_key"] == "198.51.100.10"
    assert attacker["event_counts"] == {
        "cowrie.command.input": 1,
        "cowrie.login.failed": 1,
    }
    assert attacker["commands"] == ["id"]
    assert attacker["recent_tactics"] == ["Credential Access", "Discovery"]
    assert attacker["recent_techniques"] == ["T1110", "T1033"]
    assert attacker["docker_probe_error"] is None
    assert attacker["historical_opened_assets"][0]["ports"] == ["127.0.0.1:18080->80"]
    assert (
        attacker["historical_opened_assets"][0]["current_container_status"]
        == "Up 3 seconds"
    )
    assert attacker["current_running_assets"][0]["asset_id"] == "internal-portal"
    assert attacker["decisions"][0]["action_asset_ids"] == ["internal-portal"]


def test_summarize_demo_reports_docker_probe_unavailable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        summarize_adaptive_demo,
        "current_docker_status",
        lambda: summarize_adaptive_demo.DockerStatusProbe(
            statuses={},
            error="docker access denied",
        ),
    )
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    (state_dir / "bindings.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "attacker_key": "198.51.100.10",
                        "binding_id": "binding-1",
                        "last_seen_ts": "2026-01-01T00:00:00Z",
                        "unlocked_assets": ["internal-portal"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "profiles.json").write_text(
        json.dumps({"profiles": {"198.51.100.10": {}}}),
        encoding="utf-8",
    )
    (state_dir / "asset_runtime.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "binding_id": "binding-1",
                        "asset_id": "internal-portal",
                        "asset_name": "Internal Portal",
                        "status": "running",
                        "template_family": "web-honeypot",
                        "settings": {
                            "container_name": "honeynet-bind-internal-portal",
                            "runtime_backend": "docker",
                            "image": "dtagdevsec/wordpot:24.04.1",
                            "port_mappings": [
                                {
                                    "host": "127.0.0.1",
                                    "host_port": 18080,
                                    "container_port": 80,
                                }
                            ],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "cowrie_observations.json").write_text(
        json.dumps({"observations": []}),
        encoding="utf-8",
    )
    (state_dir / "decision_trace.json").write_text(
        json.dumps({"records": []}),
        encoding="utf-8",
    )

    report = summarize_demo(state_dir)

    attacker = report["attackers"][0]
    assert attacker["docker_probe_error"] == "docker access denied"
    assert attacker["current_running_assets"] == []
    assert attacker["failed_assets"] == []
    assert attacker["historical_opened_assets"][0]["current_container_status"] == "unavailable"


def test_summarize_demo_treats_exited_container_as_historical_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    (state_dir / "cowrie_observations.json").write_text(
        json.dumps(
            {
                "observations": [
                    {
                        "attacker_key": "198.51.100.99",
                        "eventid": "cowrie.command.input",
                        "session": "s-8",
                        "timestamp": "2026-01-01T00:00:00Z",
                        "input": "whoami",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "bindings.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "binding_id": "binding-exited",
                        "attacker_key": "198.51.100.99",
                        "last_seen_ts": "2026-01-01T00:00:01Z",
                        "unlocked_assets": ["redis-cache"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "asset_runtime.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "runtime_id": "runtime-2",
                        "binding_id": "binding-exited",
                        "asset_id": "redis-cache",
                        "asset_name": "Redis Cache",
                        "status": "running",
                        "settings": {
                            "runtime_backend": "docker",
                            "container_name": "honeynet-binding-e-redis-cache",
                            "host": "127.0.0.1",
                            "host_port": 6379,
                            "container_port": 6379,
                        },
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
                    "198.51.100.99": {
                        "recent_tactics": ["Discovery"],
                        "recent_techniques": ["T1033"],
                        "conf_by_tactic": {"Discovery": 0.8},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "decision_trace.json").write_text(
        json.dumps({"records": []}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        summarize_adaptive_demo,
        "current_docker_status",
        lambda: summarize_adaptive_demo.DockerStatusProbe(
            statuses={"honeynet-binding-e-redis-cache": "Exited (0) 10 seconds ago"},
            error=None,
        ),
    )

    report = summarize_adaptive_demo.summarize_demo(state_dir)
    attacker = report["attackers"][0]

    assert attacker["current_running_assets"] == []
    assert (
        attacker["historical_opened_assets"][0]["current_container_status"]
        == "Exited (0) 10 seconds ago"
    )
    assert attacker["failed_assets"][0]["asset_id"] == "redis-cache"


def test_write_report_creates_parent_directory(tmp_path) -> None:
    report_file = tmp_path / "nested" / "adaptive_demo_report.json"

    write_report({"schema_version": "v1", "attackers": []}, report_file)

    assert json.loads(report_file.read_text(encoding="utf-8")) == {
        "schema_version": "v1",
        "attackers": [],
    }
