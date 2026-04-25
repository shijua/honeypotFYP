"""Live dashboard for the local adaptive honeynet stack."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

from libs.common.config import RuntimeConfig
from scripts.summarize_adaptive_demo import summarize_demo

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
    entrypoint_observations = _read_items(
        state_dir / "entrypoint_observations.json",
        "observations",
    )
    cowrie_observations = _read_items(
        state_dir / "cowrie_observations.json",
        "observations",
    )
    containers = _probe_project_containers(project_name)
    attackers = [
        attacker
        for attacker in report.get("attackers", [])
        if isinstance(attacker, dict)
    ]

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
            containers=containers,
        ),
        "containers": containers,
        "bindings": bindings,
        "gateway_routes": gateway_routes,
        "attackers": attackers,
        "recent_entrypoint_observations": _recent_items(entrypoint_observations),
        "recent_cowrie_observations": _recent_items(cowrie_observations),
    }


@lru_cache(maxsize=1)
def _load_dashboard_html() -> str:
    """Load the dashboard HTML once and inject the refresh interval."""
    return INDEX_HTML_PATH.read_text(encoding="utf-8").replace(
        "__REFRESH_SECONDS__",
        str(REFRESH_SECONDS),
    )


def _build_metrics(
    *,
    attackers: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
    entrypoint_observations: list[dict[str, Any]],
    cowrie_observations: list[dict[str, Any]],
    containers: list[dict[str, str]],
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


def _read_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    try:
        payload = path.read_text(encoding="utf-8")
    except OSError:
        return default
    try:
        decoded = json.loads(payload)
    except Exception:
        return default
    return decoded if isinstance(decoded, dict) else default


def _read_items(path: Path, key: str) -> list[dict[str, Any]]:
    payload = _read_json(path, {key: []})
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
