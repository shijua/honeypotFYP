from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

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
                    # Dashboard exposes these profile breadcrumbs so we can
                    # debug which public request unlocked an internal asset.
                    "recent_tactics": ["Credential Access", "Discovery"],
                    "recent_techniques": ["T1110", "T1087"],
                    "recent_public_http_paths": ["/.env"],
                    "recent_public_http_rules": ["public_http_credential_discovery"],
                    "recent_public_http_indicators": ["combined:.env"],
                    "recent_internal_http_paths": ["/finance/archive/report.zip"],
                    "recent_internal_http_rules": ["internal_http_artifact_access"],
                    "recent_internal_http_indicators": ["path:.zip"],
                    "conf_by_tactic": {"Credential Access": 0.7},
                    "updated_at": "2026-01-01T00:00:03Z",
                }
            }
        },
    )
    _write_json(
        state_dir / "evidence.json",
        {
            "records": {
                "198.51.100.10": [
                    {
                        "evidence_id": "e-public-http-2",
                        "ts": "2026-01-01T00:00:02Z",
                        "attacker_key": "198.51.100.10",
                        "binding_id": "binding-1",
                        "tech_id": "T1046",
                        "group": "Discovery",
                        "weight": 1.5,
                        "success": True,
                        "reason": "HTTP honeypot request",
                        "source_ref": {
                            "source": "public_http",
                            "http_path": "/admin",
                            "http_user_agent": "scanner/1.0",
                            "http_evidence_labels": ["public-http scanner"],
                            "http_indicators": ["path:/admin"],
                        },
                    },
                    {
                        "evidence_id": "e-public-http-old",
                        "ts": "2025-12-31T23:00:00Z",
                        "attacker_key": "198.51.100.10",
                        "binding_id": "binding-1",
                        "tech_id": "T1552.001",
                        "group": "Credential Access",
                        "weight": 1.5,
                        "success": True,
                        "reason": "Old HTTP honeypot request",
                        "source_ref": {
                            "source": "public_http",
                            "http_path": "/old.env",
                            "http_evidence_labels": ["old public-http credential"],
                            "http_indicators": ["combined:old"],
                        },
                    },
                    {
                        "evidence_id": "e-public-http-1",
                        "ts": "2026-01-01T00:00:01Z",
                        "attacker_key": "198.51.100.10",
                        "binding_id": "binding-1",
                        "tech_id": "T1552.001",
                        "group": "Credential Access",
                        "weight": 2.5,
                        "success": True,
                        "reason": "HTTP honeypot request",
                        "source_ref": {
                            "source": "public_http",
                            "http_path": "/.env",
                            "http_user_agent": "curl/8.0",
                            "http_evidence_labels": [
                                "public-http credential or backup discovery"
                            ],
                            "http_indicators": ["combined:.env"],
                        },
                    },
                    {
                        "evidence_id": "e-internal-http-old",
                        "ts": "2025-12-31T23:00:00Z",
                        "attacker_key": "198.51.100.10",
                        "binding_id": "binding-1",
                        "tech_id": "T1005",
                        "group": "Collection",
                        "weight": 1.5,
                        "success": True,
                        "reason": "Old internal HTTP request",
                        "source_ref": {
                            "source": "internal_http",
                            "http_path": "/old.zip",
                            "http_evidence_labels": ["old internal artifact"],
                            "http_indicators": ["path:old"],
                        },
                    },
                    {
                        "evidence_id": "e-internal-http-1",
                        "ts": "2026-01-01T00:00:03Z",
                        "attacker_key": "198.51.100.10",
                        "binding_id": "binding-1",
                        "tech_id": "T1005",
                        "group": "Collection",
                        "weight": 1.5,
                        "success": True,
                        "reason": "Internal HTTP asset request",
                        "source_ref": {
                            "source": "internal_http",
                            "http_path": "/finance/archive/report.zip",
                            "http_user_agent": "curl/8.0",
                            "http_evidence_labels": ["internal-http artifact access"],
                            "http_indicators": ["path:.zip"],
                        },
                    }
                ]
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
                    "matched_rules": [],
                    "tags": [],
                    "indicators": [],
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
    _write_json(
        state_dir / "opencanary_observations.json",
        {
            "observations": [
                {
                    "observation_id": "opencanary-1",
                    "attacker_key": "198.51.100.10",
                    "binding_id": "binding-1",
                    "ts": "2026-01-01T00:00:02Z",
                    "service": "redis",
                    "src_host": "198.51.100.10",
                    "dst_port": 6379,
                    "password_seen": False,
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
    opencanary_log = state_dir / "opencanary.log"
    opencanary_log.write_text(
        json.dumps(
            {
                "utc_time": "2026-01-01T00:00:02Z",
                "src_host": "198.51.100.10",
                "dst_port": 6379,
                "logdata": {"SERVICE": "redis", "PASSWORD": "do-not-render"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HONEYPOT_STATE_DIR", str(state_dir))
    monkeypatch.setenv("HONEYPOT_PROJECT_NAME", "honeynet")
    monkeypatch.setenv("HONEYPOT_COWRIE_LOG_PATH", str(cowrie_log))
    monkeypatch.setenv("HONEYPOT_OPENCANARY_LOG_PATH", str(opencanary_log))
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
                "name": "honeynet_public-portal-forwarder_1",
                "image": "python:3.10-slim",
                "status": "Up 12 seconds",
                "ports": "",
                "kind": "compose",
            },
            {
                "name": "honeynet_internal-http-forwarder_1",
                "image": "python:3.10-slim",
                "status": "Up 12 seconds",
                "ports": "",
                "kind": "compose",
            },
            {
                "name": "honeynet_opencanary-forwarder_1",
                "image": "python:3.10-slim",
                "status": "Up 12 seconds",
                "ports": "",
                "kind": "compose",
            },
            {
                "name": "honeynet_opencanary-adapter_1",
                "image": "python:3.10-slim",
                "status": "Up 12 seconds",
                "ports": "8012/tcp",
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
    assert payload["metrics"]["containers_up"] == 10
    assert payload["metrics"]["opencanary_event_count"] == 1
    assert payload["bindings"][0]["binding_id"] == "binding-1"
    assert payload["gateway_routes"][0]["exposed_assets"] == ["internal-portal"]
    assert payload["attackers"][0]["current_running_assets"][0]["asset_id"] == "internal-portal"
    assert payload["attackers"][0]["public_http_evidence"] == [
        "rule:public-http credential or backup discovery",
        "combined:.env",
        "path:/.env",
        "ua:curl/8.0",
        "rule:public-http scanner",
        "path:/admin",
        "ua:scanner/1.0",
    ]
    assert "path:/old.env" not in payload["attackers"][0]["public_http_evidence"]
    assert payload["attackers"][0]["internal_http_evidence"] == [
        "rule:internal-http artifact access",
        "path:.zip",
        "path:/finance/archive/report.zip",
        "ua:curl/8.0",
    ]
    assert "path:/old.zip" not in payload["attackers"][0]["internal_http_evidence"]
    assert payload["attackers"][0]["recent_public_http_paths"] == ["/.env"]
    assert payload["attackers"][0]["recent_public_http_rules"] == [
        "public_http_credential_discovery"
    ]
    assert payload["attackers"][0]["recent_public_http_indicators"] == ["combined:.env"]
    assert payload["metrics"]["healthy_chain_stages"] >= 6
    assert {
        stage["stage"]: stage["status"]
        for stage in payload["chain_health"]
    }["Cowrie forwarder"] == "ok"
    assert {
        stage["stage"]: stage["status"]
        for stage in payload["chain_health"]
    }["Benign surface forwarder"] == "ok"
    assert {
        stage["stage"]: stage["status"]
        for stage in payload["chain_health"]
    }["Internal HTTP forwarder"] == "ok"
    assert {
        stage["stage"]: stage["status"]
        for stage in payload["chain_health"]
    }["OpenCanary forwarder"] == "ok"
    assert "do-not-render" not in json.dumps(payload["chain_health"])
    assert payload["recent_entrypoint_observations"][0]["path"] == "/.env"
    assert payload["recent_entrypoint_observations"][0]["indicators"] == []
    assert payload["recent_cowrie_observations"][0]["command"] == "cat /etc/passwd"
    assert payload["recent_opencanary_observations"][0]["service"] == "redis"


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


def test_forwarder_startup_connection_refusal_is_warning() -> None:
    stage = dashboard_health._forwarder_stage(
        {
            "name": "honeynet_public-portal-forwarder_1",
            "status": "Up 2 seconds",
        },
        "Could not reach entrypoint observer: connection refused",
        stage="Benign surface forwarder",
        component="public-portal-forwarder",
        target="public website HTTP backend",
    )

    assert stage["status"] == "warn"


def test_probe_container_logs_sorts_docker_streams_by_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "2026-01-01T00:00:03.000000000Z Forwarded public-portal GET /ok\n"
                "2026-01-01T00:00:02.000000000Z Observer rejected public portal event with HTTP 500\n"
            ),
        )

    monkeypatch.setattr(dashboard_health.subprocess, "run", fake_run)

    lines = dashboard_health._probe_container_logs("honeynet_public-portal-forwarder_1")

    assert lines == [
        "Observer rejected public portal event with HTTP 500",
        "Forwarded public-portal GET /ok",
    ]
    assert dashboard_health._last_forwarder_log_line(
        "honeynet_public-portal-forwarder_1"
    ) == "Forwarded public-portal GET /ok"


def test_dashboard_summary_marks_compose_assets_as_running(
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
                    "unlocked_assets": ["log4shell-app"],
                }
            ]
        },
    )
    _write_json(
        state_dir / "asset_runtime.json",
        {
            "records": [
                {
                    "binding_id": "binding-1",
                    "asset_id": "log4shell-app",
                    "asset_name": "Legacy Java App",
                    "status": "running",
                    "template_family": "vulnerable-webapp-honeypot",
                    "settings": {
                        "runtime_backend": "compose",
                        "compose_project": "honeynet-binding-log4shell-app",
                        "container_names": ["honeynet-binding-log4shell-app-1"],
                    },
                }
            ]
        },
    )
    _write_json(state_dir / "profiles.json", {"profiles": {}})
    _write_json(state_dir / "cowrie_observations.json", {"observations": []})
    _write_json(state_dir / "opencanary_observations.json", {"observations": []})
    _write_json(state_dir / "decision_trace.json", {"records": []})

    monkeypatch.setattr(
        dashboard_summary,
        "current_docker_status",
        lambda: dashboard_summary.DockerStatusProbe(statuses={}, error=None),
    )
    monkeypatch.setattr(
        dashboard_summary,
        "_current_compose_statuses",
        lambda _project_name: {"honeynet-binding-log4shell-app-1": "Up 8 seconds"},
    )

    payload = dashboard_summary.summarize_demo(state_dir)

    running_assets = payload["attackers"][0]["current_running_assets"]
    assert running_assets[0]["asset_id"] == "log4shell-app"
    assert running_assets[0]["runtime_backend"] == "compose"
    assert running_assets[0]["compose_project"] == "honeynet-binding-log4shell-app"
