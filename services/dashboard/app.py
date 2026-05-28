"""Live dashboard for the local adaptive honeynet stack."""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

from libs.common.config import RuntimeConfig
from libs.common.json_utils import read_json_object
from services.dashboard.health import build_chain_health
from services.dashboard.summary import summarize_demo

app = FastAPI(title="dashboard", version="0.1.0")

APP_DIR = Path(__file__).resolve().parent
INDEX_HTML_PATH = APP_DIR / "static" / "index.html"
STATIC_DIR = APP_DIR / "static"
REFRESH_SECONDS = 3

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="dashboard-static")


@app.get("/", response_class=HTMLResponse)
def dashboard_index() -> HTMLResponse:
    """Serve the live monitoring dashboard."""
    return HTMLResponse(_load_dashboard_html())


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Simple liveness endpoint for compose smoke checks."""
    return {"status": "ok"}


@app.get("/api/summary")
def api_summary() -> dict[str, Any]:
    """Return one pollable JSON snapshot for the dashboard."""
    state_dir = _state_dir()
    project_name = _project_name()
    report = summarize_demo(state_dir)

    bindings = _sorted_records(
        _read_items(state_dir / "bindings.json", "records"),
        "last_seen_ts",
    )
    gateway_routes = _sorted_records(
        _read_items(state_dir / "gateway_routes.json", "routes"),
        "updated_at",
    )
    asset_gateway_routes = _sorted_records(
        _read_items(state_dir / "asset_gateway_routes.json", "routes"),
        "updated_at",
    )
    entrypoint_observations = _read_items(
        state_dir / "entrypoint_observations.json",
        "observations",
    )
    cowrie_observations = _read_items(
        state_dir / "cowrie_observations.json",
        "observations",
    )
    opencanary_observations = _read_items(
        state_dir / "opencanary_observations.json",
        "observations",
    )
    high_interaction_observations = _read_items(
        state_dir / "high_interaction_observations.json",
        "observations",
    )
    decision_trace = _read_items(state_dir / "decision_trace.json", "records")
    containers = _probe_project_containers(project_name)
    attackers = [
        attacker
        for attacker in report.get("attackers", [])
        if isinstance(attacker, dict)
    ]
    chain_health = build_chain_health(
        project_name=project_name,
        state_dir=state_dir,
        containers=containers,
        bindings=bindings,
        gateway_routes=gateway_routes,
        attackers=attackers,
        entrypoint_observations=entrypoint_observations,
        cowrie_observations=cowrie_observations,
        opencanary_observations=opencanary_observations,
        high_interaction_observations=high_interaction_observations,
        decision_trace=decision_trace,
    )

    return {
        "schema_version": "v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_name": project_name,
        "state_dir": str(state_dir),
        "metrics": _build_metrics(
            attackers=attackers,
            bindings=bindings,
            entrypoint_observations=entrypoint_observations,
            cowrie_observations=cowrie_observations,
            opencanary_observations=opencanary_observations,
            high_interaction_observations=high_interaction_observations,
            containers=containers,
            chain_health=chain_health,
            asset_gateway_routes=asset_gateway_routes,
        ),
        "containers": containers,
        "chain_health": chain_health,
        "bindings": bindings,
        "gateway_routes": gateway_routes,
        "asset_gateway_routes": asset_gateway_routes,
        "attackers": attackers,
        "recent_entrypoint_observations": _recent_items(entrypoint_observations),
        "recent_cowrie_observations": _recent_items(cowrie_observations),
        "recent_opencanary_observations": _recent_items(opencanary_observations),
        "recent_high_interaction_observations": _recent_items(high_interaction_observations),
    }


def _load_dashboard_html() -> str:
    """Load dashboard HTML and inject runtime-only placeholders."""
    static_version = str(
        max(
            (STATIC_DIR / "dashboard.css").stat().st_mtime_ns,
            (STATIC_DIR / "dashboard.js").stat().st_mtime_ns,
        )
    )
    return INDEX_HTML_PATH.read_text(encoding="utf-8").replace(
        "__REFRESH_SECONDS__",
        str(REFRESH_SECONDS),
    ).replace(
        "__STATIC_VERSION__",
        static_version,
    )


def _build_metrics(
    *,
    attackers: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
    entrypoint_observations: list[dict[str, Any]],
    cowrie_observations: list[dict[str, Any]],
    opencanary_observations: list[dict[str, Any]],
    high_interaction_observations: list[dict[str, Any]],
    containers: list[dict[str, str]],
    chain_health: list[dict[str, str]],
    asset_gateway_routes: list[dict[str, Any]],
) -> dict[str, int]:
    """Compute dashboard counters from one snapshot."""
    return {
        "attacker_count": len(attackers),
        "active_bindings": sum(
            1
            for binding in bindings
            if str(binding.get("status", "")).lower() == "active"
        ),
        "running_assets": sum(
            len(attacker.get("current_running_assets", []))
            for attacker in attackers
        ),
        "failed_assets": sum(
            len(attacker.get("failed_assets", []))
            for attacker in attackers
        ),
        "entrypoint_event_count": len(entrypoint_observations),
        "cowrie_event_count": len(cowrie_observations),
        "opencanary_event_count": len(opencanary_observations),
        "high_interaction_event_count": len(high_interaction_observations),
        "containers_up": sum(
            1
            for container in containers
            if str(container.get("status", "")).startswith("Up")
        ),
        "published_port_count": sum(
            1
            for container in containers
            if isinstance(container.get("ports"), str) and container.get("ports")
        ),
        "asset_gateway_route_count": len(asset_gateway_routes),
        "healthy_chain_stages": sum(
            1
            for stage in chain_health
            if stage.get("status") == "ok"
        ),
        "warning_chain_stages": sum(
            1
            for stage in chain_health
            if stage.get("status") in {"warn", "bad"}
        ),
    }


def _project_name() -> str:
    return os.getenv("HONEYPOT_PROJECT_NAME", "honeynet")


def _state_dir() -> Path:
    return Path(os.getenv("HONEYPOT_STATE_DIR", RuntimeConfig().state_dir))


def _recent_items(
    records: list[dict[str, Any]],
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    return list(reversed(records[-limit:]))


def _read_items(path: Path, key: str) -> list[dict[str, Any]]:
    payload = read_json_object(path, {key: []})
    items = payload.get(key, [])
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _sorted_records(records: list[dict[str, Any]], sort_key: str) -> list[dict[str, Any]]:
    return sorted(records, key=lambda item: str(item.get(sort_key, "")), reverse=True)


def _probe_project_containers(project_name: str) -> list[dict[str, str]]:
    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"name={project_name}",
                "--format",
                "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        return [_diagnostic_container("docker-unavailable", str(exc))]
    if result.returncode != 0:
        error = result.stderr.strip() or f"docker ps failed with code {result.returncode}"
        return [_diagnostic_container("docker-error", error)]

    containers: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        name, _, remainder = line.partition("\t")
        image, _, remainder = remainder.partition("\t")
        status, _, ports = remainder.partition("\t")
        if not name:
            continue
        containers.append(
            {
                "name": name,
                "image": image,
                "status": status,
                "ports": ports,
                "kind": "compose" if name.endswith("_1") else "runtime",
            }
        )
    return sorted(containers, key=lambda item: item["name"])


def _diagnostic_container(name: str, status: str) -> dict[str, str]:
    return {
        "name": name,
        "image": "-",
        "status": status,
        "ports": "",
        "kind": "diagnostic",
    }
