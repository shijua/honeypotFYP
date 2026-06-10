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
                    "conf_by_technique": {"T1110": 0.6321, "T1087": 0.3935},
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
                    },
                    {
                        "evidence_id": "e-cowrie-command-1",
                        "ts": "2026-01-01T00:00:02Z",
                        "attacker_key": "198.51.100.10",
                        "binding_id": "binding-1",
                        "tech_id": "T1087.001",
                        "group": "Discovery",
                        "weight": 2.0,
                        "success": True,
                        "reason": "cowrie.command.input",
                        "source_ref": {
                            "source": "cowrie",
                            "output": "cowrie.command.input from 198.51.100.10: cat /etc/passwd [local_account_file_discovery]",
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
                },
                {
                    "binding_id": "binding-1",
                    "asset_id": "redis-cache",
                    "asset_name": "Redis Cache",
                    "status": "stopped",
                    "template_family": "cache-service",
                    "settings": {
                        "container_name": "honeynet-bind-redis-cache",
                        "runtime_backend": "docker",
                        "image": "opencanary:local",
                        "port_mappings": [
                            {
                                "host": "146.169.44.23",
                                "host_port": 16379,
                                "container_port": 6379,
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
                    "recent_evidence_ids": ["e-public-http-1", "e-cowrie-command-1"],
                    "candidate_asset_ids": ["internal-portal"],
                    "actions": [{"action_type": "unlock", "asset_id": "internal-portal"}],
                    "decision_events": [
                        {
                            "ts": "2026-01-01T00:00:03Z",
                            "decision_type": "unlock",
                            "asset_added": "internal-portal",
                            "reason": "exploit selected internal-portal via T1087",
                            "details": {
                                "selected_strategy": "exploit",
                                "reveal_role": "main",
                                "candidate_type": "observed",
                                "selected_technique": "T1087",
                                "confidence_score": 0.8,
                                "recommendation_support": 0.3,
                                "expected_technique_gain": 0.6,
                                "covered_techniques": ["T1087", "T1110"],
                                "gain_terms": [
                                    {
                                        "technique": "T1087",
                                        "support": 0.3,
                                        "confidence": 0.8,
                                        "gain": 0.06,
                                    },
                                    {
                                        "technique": "T1110",
                                        "support": 0.54,
                                        "confidence": 0.0,
                                        "gain": 0.54,
                                    },
                                ],
                                "asset_group": "portal",
                                "eligible_assets": ["internal-portal"],
                                "eligible_reveal_options": [
                                    {
                                        "action_type": "unlock",
                                        "asset_id": "internal-portal",
                                    }
                                ],
                                "rejected_assets": {"finance-share": "dependency not met"},
                                "matched_dependency_markers": ["any_http_indicators:combined:.env"],
                                "observed_techniques": ["T1110", "T1087"],
                                "prior_support_enabled": True,
                                "prior_degraded": None,
                            },
                        }
                    ],
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
    assert payload["metrics"]["failed_assets"] == 0
    assert payload["metrics"]["containers_up"] == 10
    assert payload["metrics"]["opencanary_event_count"] == 1
    assert payload["bindings"][0]["binding_id"] == "binding-1"
    assert payload["gateway_routes"][0]["exposed_assets"] == ["internal-portal"]
    assert payload["attackers"][0]["current_running_assets"][0]["asset_id"] == "internal-portal"
    assert payload["attackers"][0]["failed_assets"] == []
    assert "reveal_feedback" not in payload["attackers"][0]
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
    assert payload["attackers"][0]["confidence_by_technique"] == {
        "T1110": 0.6321,
        "T1087": 0.3935,
    }
    decision = payload["attackers"][0]["decisions"][0]
    assert decision["trigger_evidence"] == [
        {
            "evidence_id": "e-public-http-1",
            "source": "public_http",
            "label": "HTTP honeypot request",
            "detail": "HTTP /.env",
            "text": "public_http:HTTP /.env",
        },
        {
            "evidence_id": "e-cowrie-command-1",
            "source": "cowrie",
            "label": "cowrie.command.input",
            "detail": "cat /etc/passwd",
            "text": "cmd:cat /etc/passwd",
        },
    ]
    assert decision["actions"] == [
        {
            "action_type": "unlock",
            "asset_id": "internal-portal",
            "configuration_id": None,
            "target_asset_id": None,
        }
    ]
    assert decision["decision_events"][0]["reveal_role"] == "main"
    assert decision["decision_events"][0]["selected_technique"] == "T1087"
    assert decision["decision_events"][0]["eligible_reveal_option_count"] == 1
    assert decision["decision_events"][0]["eligible_reveal_options"] == [
        {
            "action_type": "unlock",
            "asset_id": "internal-portal",
            "configuration_id": None,
            "target_asset_id": None,
        }
    ]
    assert decision["decision_events"][0]["rejected_asset_count"] == 1
    assert decision["decision_events"][0]["rejection_reason_counts"] == {
        "dependency not met": 1
    }
    assert decision["decision_events"][0]["prior_support_enabled"] is True
    assert decision["decision_events"][0]["covered_techniques"] == ["T1087", "T1110"]
    assert decision["decision_events"][0]["gain_terms"] == [
        {"technique": "T1087", "support": 0.3, "confidence": 0.8, "gain": 0.06},
        {"technique": "T1110", "support": 0.54, "confidence": 0.0, "gain": 0.54},
    ]
    assert decision["decision_events"][0]["observed_techniques"] == ["T1110", "T1087"]
    assert decision["decision_events"][0]["matched_dependency_markers"] == [
        "any_http_indicators:combined:.env"
    ]
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
    assert ".decision-flow" in css
    assert ".decision-waiting" in css
    assert "async function loadData()" in js
    assert "function renderHealth" in js
    assert "function techniqueBadgeList" in js
    assert "function formatRejectionReason" in js
    assert "function decisionSortKey" in js
    assert "decisionSortKey(right).localeCompare(decisionSortKey(left))" in js
    assert "waiting for ${noun}" in js
    assert "gain terms:" in js
    assert "function gainTermLabels" in js
    assert "total gain" in js
    assert 'detailOpenAttribute(detailKey, hasRevealAction)' in js
    assert 'class="trace-label">Gate' in js
    assert 'class="trace-label">Rank' in js
    assert 'class="trace-label">Action' in js
    assert 'class="trace-label">Triggered by' in js
    assert "waiting_for_reveal_response" in js


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
                    "unlocked_assets": ["compose-web-lab"],
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
                    "asset_id": "compose-web-lab",
                    "asset_name": "Optional Compose Web Lab",
                    "status": "running",
                    "template_family": "compose-web-lab",
                    "settings": {
                        "runtime_backend": "compose",
                        "compose_project": "honeynet-binding-compose-web-lab",
                        "container_names": ["honeynet-binding-compose-web-lab-1"],
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
        lambda _project_name: {"honeynet-binding-compose-web-lab-1": "Up 8 seconds"},
    )

    payload = dashboard_summary.summarize_demo(state_dir)

    running_assets = payload["attackers"][0]["current_running_assets"]
    assert running_assets[0]["asset_id"] == "compose-web-lab"
    assert running_assets[0]["runtime_backend"] == "compose"
    assert running_assets[0]["compose_project"] == "honeynet-binding-compose-web-lab"


def test_dashboard_summary_ignores_stale_failed_runtime_after_target_swap(
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
                    "unlocked_assets": ["git-internal"],
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
                    "asset_id": "git-internal",
                    "asset_name": "Git Internal",
                    "status": "running",
                    "template_family": "git-service",
                    "settings": {
                        "container_name": "honeynet-binding-old-git-internal",
                        "runtime_backend": "docker",
                        "image": "alpine/git:latest",
                    },
                },
                {
                    "binding_id": "binding-1",
                    "asset_id": "git-internal",
                    "asset_name": "Git Internal",
                    "status": "running",
                    "template_family": "git-service",
                    "settings": {
                        "container_name": "honeynet-binding-new-git-internal",
                        "runtime_backend": "docker",
                        "image": "alpine:3.20",
                        "configured_runtime": True,
                        "active_configurations": {
                            "git-seeded-repository-backend": {
                                "configuration_id": "git-seeded-repository-backend"
                            }
                        },
                    },
                },
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
        lambda: dashboard_summary.DockerStatusProbe(
            statuses={
                "honeynet-binding-old-git-internal": "Exited (128) 10 seconds ago",
                "honeynet-binding-new-git-internal": "Up 8 seconds",
            },
            error=None,
        ),
    )

    payload = dashboard_summary.summarize_demo(state_dir)

    running_container_names = [
        asset["container_name"]
        for asset in payload["attackers"][0]["current_running_assets"]
    ]
    assert running_container_names == [
        "honeynet-binding-new-git-internal"
    ]
    running_asset = payload["attackers"][0]["current_running_assets"][0]
    assert running_asset["configured_runtime"] is True
    assert running_asset["active_configuration_ids"] == [
        "git-seeded-repository-backend"
    ]
    assert payload["attackers"][0]["failed_assets"] == []
