from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.dashboard import summary as dashboard_summary
from services.dashboard import app as dashboard_app
from services.dashboard import health as dashboard_health


pytestmark = pytest.mark.component


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_dashboard_summary_endpoint_returns_live_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    _write_json(
        state_dir / "bindings.json",
        {
            "records": [
                {
                    "binding_id": "binding-1",
                    "attacker_key": "198.51.100.10",
                    "status": "active",
                    "last_seen_ts": "2026-01-01T00:00:02Z",
                    "unlocked_assets": ["internal-portal"],
                }
            ]
        },
    )
    _write_json(
        state_dir / "profiles.json",
        {
            "profiles": {
                "198.51.100.10": {
                    "recent_tactics": ["Credential Access", "Discovery"],
                    "recent_techniques": ["T1110", "T1087"],
                    "conf_by_tactic": {"Credential Access": 0.7},
                }
            }
        },
    )
    _write_json(
        state_dir / "asset_runtime.json",
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
                        "image": "nginx:alpine",
                        "port_mappings": [
                            {
                                "host": "146.169.44.23",
                                "host_port": 18080,
                                "container_port": 80,
                            }
                        ],
                    },
                }
            ]
        },
    )
    _write_json(
        state_dir / "decision_trace.json",
        {
            "records": [
                {
                    "attacker_key": "198.51.100.10",
                    "ts": "2026-01-01T00:00:03Z",
                    "candidate_asset_ids": ["internal-portal"],
                    "actions": [{"action_type": "unlock", "asset_id": "internal-portal"}],
                    "decision_events": [{"reason": "selected internal-portal"}],
                }
            ]
        },
    )
    _write_json(
        state_dir / "gateway_routes.json",
        {
            "routes": [
                {
                    "binding_id": "binding-1",
                    "attacker_key": "198.51.100.10",
                    "backend_instance_id": "ns-binding-1",
                    "status": "active",
                    "exposed_assets": ["internal-portal"],
                    "failed_assets": [],
                    "route_updates": ["binding binding-1 exposes internal-portal"],
                    "updated_at": "2026-01-01T00:00:04Z",
                }
            ]
        },
    )
    _write_json(
        state_dir / "entrypoint_observations.json",
        {
            "observations": [
                {
                    "observation_id": "obs-1",
                    "binding_id": "binding-1",
                    "attacker_key": "198.51.100.10",
                    "ts": "2026-01-01T00:00:01Z",
                    "method": "GET",
                    "path": "/.env",
                    "response_status": 404,
                }
            ]
        },
    )
    _write_json(
        state_dir / "cowrie_observations.json",
        {
            "observations": [
                {
                    "observation_id": "cowrie-1",
                    "attacker_key": "198.51.100.10",
                    "ts": "2026-01-01T00:00:02Z",
                    "eventid": "cowrie.command.input",
                    "command": "cat /etc/passwd",
                    "session": "session-1",
                }
            ]
        },
    )
    cowrie_log = state_dir / "cowrie.json"
    cowrie_log.write_text(
        json.dumps(
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-01-01T00:00:02Z",
                "src_ip": "198.51.100.10",
                "session": "session-1",
                "input": "cat /etc/passwd",
                "password": "do-not-render",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HONEYPOT_STATE_DIR", str(state_dir))
    monkeypatch.setenv("HONEYPOT_PROJECT_NAME", "honeynet")
    monkeypatch.setenv("HONEYPOT_COWRIE_LOG_PATH", str(cowrie_log))
    monkeypatch.setattr(
        dashboard_summary,
        "current_docker_status",
        lambda: dashboard_summary.DockerStatusProbe(
            statuses={"honeynet-bind-internal-portal": "Up 5 seconds"},
            error=None,
        ),
    )
    monkeypatch.setattr(
        dashboard_app,
        "_probe_project_containers",
        lambda _project_name: [
            {
                "name": "honeynet_public-portal_1",
                "image": "nginx:alpine",
                "status": "Up 12 seconds",
                "ports": "146.169.44.23:8080->80/tcp",
                "kind": "compose",
            },
            {
                "name": "honeynet_entrypoint-observer_1",
                "image": "python:3.10-slim",
                "status": "Up 12 seconds",
                "ports": "146.169.44.23:8083->8010/tcp",
                "kind": "compose",
            },
            {
                "name": "honeynet_cowrie-forwarder_1",
                "image": "python:3.10-slim",
                "status": "Up 12 seconds",
                "ports": "",
                "kind": "compose",
            },
            {
                "name": "honeynet_cowrie-adapter_1",
                "image": "python:3.10-slim",
                "status": "Up 12 seconds",
                "ports": "8011/tcp",
                "kind": "compose",
            },
            {
                "name": "honeynet_dashboard_1",
                "image": "python:3.10-slim",
                "status": "Up 12 seconds",
                "ports": "146.169.44.23:8090->8090/tcp",
                "kind": "compose",
            },
            {
                "name": "honeynet-bind-internal-portal",
                "image": "nginx:alpine",
                "status": "Up 5 seconds",
                "ports": "146.169.44.23:18080->80/tcp",
                "kind": "runtime",
            },
        ],
    )
    monkeypatch.setattr(
        dashboard_health,
        "_probe_container_logs",
        lambda _container_name: ["Forwarded cowrie.command.input"],
    )

    payload = dashboard_app.api_summary()

    assert payload["metrics"]["attacker_count"] == 1
    assert payload["metrics"]["active_bindings"] == 1
    assert payload["metrics"]["running_assets"] == 1
    assert payload["metrics"]["containers_up"] == 6
    assert payload["bindings"][0]["binding_id"] == "binding-1"
    assert payload["gateway_routes"][0]["exposed_assets"] == ["internal-portal"]
    assert payload["attackers"][0]["current_running_assets"][0]["asset_id"] == "internal-portal"
    assert payload["metrics"]["healthy_chain_stages"] >= 6
    assert {
        stage["stage"]: stage["status"]
        for stage in payload["chain_health"]
    }["Cowrie forwarder"] == "ok"
    assert "do-not-render" not in json.dumps(payload["chain_health"])
    assert payload["recent_entrypoint_observations"][0]["path"] == "/.env"
    assert payload["recent_cowrie_observations"][0]["command"] == "cat /etc/passwd"


def test_dashboard_index_serves_html() -> None:
    response = dashboard_app.dashboard_index()
    css = (dashboard_app.STATIC_DIR / "dashboard.css").read_text(encoding="utf-8")
    js = (dashboard_app.STATIC_DIR / "dashboard.js").read_text(encoding="utf-8")

    assert response.status_code == 200
    assert "Live Honeynet Dashboard" in response.body.decode("utf-8")
    assert '/static/dashboard.css' in response.body.decode("utf-8")
    assert '/static/dashboard.js' in response.body.decode("utf-8")
    assert ".metrics" in css
    assert ".status-badge" in css
    assert "async function loadData()" in js
    assert "function renderHealth" in js
