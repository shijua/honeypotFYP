"""Pipeline health helpers for the live honeynet dashboard."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Callable

from libs.common.config import RuntimeConfig


def build_chain_health(
    *,
    project_name: str,
    state_dir: Path,
    containers: list[dict[str, str]],
    bindings: list[dict[str, Any]],
    gateway_routes: list[dict[str, Any]],
    attackers: list[dict[str, Any]],
    entrypoint_observations: list[dict[str, Any]],
    cowrie_observations: list[dict[str, Any]],
    opencanary_observations: list[dict[str, Any]],
    high_interaction_observations: list[dict[str, Any]],
    decision_trace: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Build a visible health trace for the attacker telemetry pipeline."""
    raw_cowrie_event = _last_json_log_event(_cowrie_log_path(), _safe_cowrie_log_event)
    raw_opencanary_event = _last_json_log_event(
        _opencanary_log_path(),
        _safe_opencanary_log_event,
    )
    internal_http_events_path = state_dir / "internal_http_events.jsonl"
    high_interaction_events_path = state_dir / "high_interaction_events.jsonl"
    raw_internal_http_event = _last_json_log_event(
        internal_http_events_path,
        _safe_internal_http_event,
    )
    raw_high_interaction_event = _last_json_log_event(
        high_interaction_events_path,
        _safe_high_interaction_event,
    )
    cowrie_forwarder, cowrie_forwarder_log = _forwarder_probe(
        project_name,
        containers,
        "cowrie-forwarder",
    )
    public_portal_forwarder, public_portal_forwarder_log = _forwarder_probe(
        project_name,
        containers,
        "public-portal-forwarder",
    )
    opencanary_forwarder, opencanary_forwarder_log = _forwarder_probe(
        project_name,
        containers,
        "opencanary-forwarder",
    )
    internal_http_forwarder, internal_http_forwarder_log = _forwarder_probe(
        project_name,
        containers,
        "internal-http-forwarder",
    )
    high_interaction_forwarder, high_interaction_forwarder_log = _forwarder_probe(
        project_name,
        containers,
        "high-interaction-forwarder",
    )
    latest_entrypoint = _latest_record(entrypoint_observations, "ts")
    latest_cowrie = _latest_record(cowrie_observations, "ts")
    latest_opencanary = _latest_record(opencanary_observations, "ts")
    latest_high_interaction = _latest_record(high_interaction_observations, "ts")
    latest_decision = _latest_record(decision_trace, "ts")
    latest_route = _latest_record(gateway_routes, "updated_at")
    technique_prior = _technique_prior_stage(Path(RuntimeConfig.from_env().attack_group_prior_path))

    stages = [
        _service_stage(
            project_name,
            containers,
            service_name="public-portal",
            stage="Benign surface",
            detail="public portal container",
        ),
        _forwarder_stage(
            public_portal_forwarder,
            public_portal_forwarder_log,
            stage="Benign surface forwarder",
            component="public-portal-forwarder",
            target="public website HTTP backend",
        ),
        _service_stage(
            project_name,
            containers,
            service_name="asset-gateway",
            stage="Asset data-plane gateway",
            detail="fixed public ports route to per-attacker backend containers",
        ),
        _raw_internal_http_stage(raw_internal_http_event),
        _forwarder_stage(
            internal_http_forwarder,
            internal_http_forwarder_log,
            stage="Internal HTTP forwarder",
            component="internal-http-forwarder",
            target="entrypoint-observer",
        ),
        _service_stage(
            project_name,
            containers,
            service_name="entrypoint-observer",
            stage="Public HTTP backend",
            detail=_record_detail(latest_entrypoint, ["method", "path", "attacker_key"]),
            empty_detail="waiting for public portal breadcrumb or direct HTTP probe",
        ),
    ]
    stages.extend(
        [
            _raw_opencanary_stage(raw_opencanary_event),
            _forwarder_stage(
                opencanary_forwarder,
                opencanary_forwarder_log,
                stage="OpenCanary forwarder",
                component="opencanary-forwarder",
                target="opencanary-adapter",
            ),
            _service_stage(
                project_name,
                containers,
                service_name="opencanary-adapter",
                stage="OpenCanary adapter",
                detail=_record_detail(
                    latest_opencanary,
                    ["service", "dst_port", "attacker_key"],
                ),
                empty_detail="adapter is up, waiting for stored OpenCanary observation",
            ),
            _raw_cowrie_stage(raw_cowrie_event),
            _forwarder_stage(
                cowrie_forwarder,
                cowrie_forwarder_log,
                stage="Cowrie forwarder",
                component="cowrie-forwarder",
                target="cowrie-adapter",
            ),
            _service_stage(
                project_name,
                containers,
                service_name="cowrie-adapter",
                stage="Cowrie adapter",
                detail=_record_detail(latest_cowrie, ["eventid", "command", "attacker_key"]),
                empty_detail="adapter is up, waiting for stored Cowrie observation",
            ),
            _raw_high_interaction_stage(raw_high_interaction_event),
            _forwarder_stage(
                high_interaction_forwarder,
                high_interaction_forwarder_log,
                stage="High-interaction forwarder",
                component="high-interaction-forwarder",
                target="high-interaction-adapter",
            ),
            _service_stage(
                project_name,
                containers,
                service_name="high-interaction-adapter",
                stage="High-interaction adapter",
                detail=_record_detail(
                    latest_high_interaction,
                    ["source", "service", "event_type", "attacker_key"],
                ),
                empty_detail="adapter is up, waiting for Dionaea/Honeytrap telemetry",
            ),
            _profile_stage(attackers, bindings, latest_decision),
            technique_prior,
            _gateway_stage(latest_route),
            _service_stage(
                project_name,
                containers,
                service_name="dashboard",
                stage="Dashboard",
                detail=f"state dir {state_dir}",
            ),
        ]
    )
    return stages


def _service_stage(
    project_name: str,
    containers: list[dict[str, str]],
    *,
    service_name: str,
    stage: str,
    detail: str,
    empty_detail: str | None = None,
) -> dict[str, str]:
    container = _container_for_service(project_name, containers, service_name)
    status = _container_health_status(container)
    if status == "ok":
        stage_detail = detail or empty_detail or "container is running"
    elif container is None:
        stage_detail = "container not found"
    else:
        stage_detail = container.get("status", "container is not running")
    return _health_stage(
        stage=stage,
        component=service_name,
        status=status,
        signal=container.get("status", "missing") if container else "missing",
        detail=stage_detail,
    )


def _raw_cowrie_stage(event: dict[str, Any] | None) -> dict[str, str]:
    return _raw_log_stage(
        stage="Cowrie raw log",
        event=event,
        missing_component="deploy/cowrie/var/log/cowrie/cowrie.json",
        present_component="cowrie.json",
        missing_detail="waiting for Cowrie to write a JSON event",
        signal_field="eventid",
        detail_fields=["timestamp", "src_ip", "input", "session"],
    )


def _raw_opencanary_stage(event: dict[str, Any] | None) -> dict[str, str]:
    return _raw_log_stage(
        stage="OpenCanary raw log",
        event=event,
        missing_component="deploy/opencanary/var/opencanary.log",
        present_component="opencanary.log",
        missing_detail="waiting for an unlocked OpenCanary internal asset to write a JSON event",
        signal_field="service",
        fallback_signal_field="dst_port",
        detail_fields=["utc_time", "src_host", "dst_port", "service"],
    )


def _raw_internal_http_stage(event: dict[str, Any] | None) -> dict[str, str]:
    return _raw_log_stage(
        stage="Internal HTTP raw log",
        event=event,
        missing_component="data/runtime/internal_http_events.jsonl",
        present_component="internal_http_events.jsonl",
        missing_detail="waiting for asset-gateway to observe an unlocked HTTP asset request",
        signal_field="path",
        detail_fields=["attacker_key", "asset_id", "method", "path"],
    )


def _raw_high_interaction_stage(event: dict[str, Any] | None) -> dict[str, str]:
    return _raw_log_stage(
        stage="High-interaction raw log",
        event=event,
        missing_component="data/runtime/high_interaction_events.jsonl",
        present_component="high_interaction_events.jsonl",
        missing_detail="waiting for asset-gateway or backend sidecar to observe upgraded TCP interaction",
        signal_field="event_type",
        detail_fields=["source", "asset_id", "service", "attacker_key"],
    )


def _raw_log_stage(
    *,
    stage: str,
    event: dict[str, Any] | None,
    missing_component: str,
    present_component: str,
    missing_detail: str,
    signal_field: str,
    detail_fields: list[str],
    fallback_signal_field: str | None = None,
) -> dict[str, str]:
    """Build one raw-log health row while preserving source-specific labels."""
    if event is None:
        return _health_stage(
            stage=stage,
            component=missing_component,
            status="warn",
            signal="no raw event",
            detail=missing_detail,
        )
    signal_value = event.get(signal_field)
    if signal_value in (None, "") and fallback_signal_field is not None:
        signal_value = event.get(fallback_signal_field)
    return _health_stage(
        stage=stage,
        component=present_component,
        status="ok",
        signal=str(signal_value or "event"),
        detail=_record_detail(event, detail_fields),
    )


def _forwarder_stage(
    container: dict[str, str] | None,
    log_line: str,
    *,
    stage: str,
    component: str,
    target: str,
) -> dict[str, str]:
    container_status = _container_health_status(container)
    if container_status != "ok":
        return _health_stage(
            stage=stage,
            component=component,
            status=container_status,
            signal=container.get("status", "missing") if container else "missing",
            detail="forwarder container is not running",
        )
    if not log_line:
        return _health_stage(
            stage=stage,
            component=component,
            status="warn",
            signal=container.get("status", "running") if container else "running",
            detail="running, no forwarded event logged yet",
        )
    if (
        "Adapter rejected" in log_line
        or "Observer rejected" in log_line
        or "Observer returned" in log_line
    ):
        status = "bad"
    elif "Could not reach" in log_line:
        status = "warn"
    elif log_line.startswith("Forwarded "):
        status = "ok"
    else:
        status = "warn"
    return _health_stage(
        stage=stage,
        component=component,
        status=status,
        signal=log_line,
        detail=f"tails JSON logs and POSTs events into {target}",
    )


def _profile_stage(
    attackers: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
    latest_decision: dict[str, Any] | None,
) -> dict[str, str]:
    if not attackers:
        return _health_stage(
            stage="Profile/controller",
            component="profiler + controller",
            status="warn",
            signal="no attacker profile",
            detail=f"{len(bindings)} binding records, waiting for profile evidence",
        )
    detail = _record_detail(latest_decision, ["ts", "attacker_key", "candidate_asset_ids"])
    return _health_stage(
        stage="Profile/controller",
        component="profiler + controller",
        status="ok",
        signal=f"{len(attackers)} attacker profiles",
        detail=detail or "profiles available",
    )


def _technique_prior_stage(path: Path) -> dict[str, str]:
    """Report whether the ATT&CK group-technique prior is available.

    Example:
        missing data/technique_prior/attack_group_technique_prior.json -> WARN
    """
    if not path.exists():
        return _health_stage(
            stage="Technique group prior",
            component=str(path),
            status="warn",
            signal="missing",
            detail="controller will run without ATT&CK group recommendations until the prior builder is run",
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _health_stage(
            stage="Technique group prior",
            component=str(path),
            status="bad",
            signal="unreadable",
            detail=str(exc),
        )
    groups = payload.get("groups") if isinstance(payload, dict) else None
    if not isinstance(groups, list) or not groups:
        return _health_stage(
            stage="Technique group prior",
            component=str(path),
            status="warn",
            signal="empty",
            detail="prior file exists but contains no ATT&CK groups",
        )
    technique_count = payload.get("technique_count") if isinstance(payload, dict) else None
    return _health_stage(
        stage="Technique group prior",
        component=str(path),
        status="ok",
        signal=f"{len(groups)} groups",
        detail=f"{technique_count or 'unknown'} techniques from ATT&CK group uses relationships",
    )


def _gateway_stage(latest_route: dict[str, Any] | None) -> dict[str, str]:
    if latest_route is None:
        return _health_stage(
            stage="Gateway/assets",
            component="gateway + orchestrator",
            status="warn",
            signal="no route",
            detail="waiting for controller/orchestrator route update",
        )
    failed_assets = latest_route.get("failed_assets", [])
    failed_assets = failed_assets if isinstance(failed_assets, list) else []
    exposed_assets = latest_route.get("exposed_assets", [])
    exposed_assets = exposed_assets if isinstance(exposed_assets, list) else []
    status = "bad" if failed_assets else "ok"
    signal = "failed assets" if failed_assets else f"{len(exposed_assets)} exposed assets"
    detail = _record_detail(
        latest_route,
        ["updated_at", "attacker_key", "exposed_assets", "failed_assets"],
    )
    return _health_stage(
        stage="Gateway/assets",
        component="gateway + orchestrator",
        status=status,
        signal=signal,
        detail=detail,
    )


def _health_stage(
    *,
    stage: str,
    component: str,
    status: str,
    signal: str,
    detail: str,
) -> dict[str, str]:
    return {
        "stage": stage,
        "component": component,
        "status": status,
        "signal": signal,
        "detail": detail,
    }


def _container_for_service(
    project_name: str,
    containers: list[dict[str, str]],
    service_name: str,
) -> dict[str, str] | None:
    expected = f"{project_name}_{service_name}_1"
    for container in containers:
        if container.get("name") == expected:
            return container
    return None


def _container_health_status(container: dict[str, str] | None) -> str:
    if container is None:
        return "bad"
    status = container.get("status", "")
    if status.startswith("Up"):
        return "ok"
    return "bad"


def _forwarder_probe(
    project_name: str,
    containers: list[dict[str, str]],
    service_name: str,
) -> tuple[dict[str, str] | None, str]:
    """Return one forwarder container plus the newest useful log line."""
    container = _container_for_service(project_name, containers, service_name)
    log_line = _last_forwarder_log_line(container.get("name") if container else "")
    return container, log_line


def _latest_record(records: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    if not records:
        return None
    return sorted(records, key=lambda item: str(item.get(key, "")))[-1]


def _record_detail(record: dict[str, Any] | None, fields: list[str]) -> str:
    if not record:
        return ""
    parts: list[str] = []
    for field in fields:
        value = record.get(field)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (list, dict)):
            value = json.dumps(value, sort_keys=True)
        parts.append(f"{field}={value}")
    return ", ".join(parts)


def _cowrie_log_path() -> Path:
    return Path(
        os.getenv(
            "HONEYPOT_COWRIE_LOG_PATH",
            "deploy/cowrie/var/log/cowrie/cowrie.json",
        )
    )


def _opencanary_log_path() -> Path:
    return Path(
        os.getenv(
            "HONEYPOT_OPENCANARY_LOG_PATH",
            "deploy/opencanary/var/opencanary.log",
        )
    )


def _last_json_log_event(
    path: Path,
    sanitizer: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any] | None:
    """Return the newest JSON object from a log file tail after sanitizing it.

    Example:
        _last_json_log_event(Path("cowrie.json"), _safe_cowrie_log_event)
        reads only the final chunk and returns safe display fields.
    """
    if not path.exists():
        return None
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(size - 65536, 0), os.SEEK_SET)
            payload = handle.read().decode("utf-8", errors="ignore")
    except OSError:
        return None
    for line in reversed(payload.splitlines()):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            return sanitizer(event)
    return None


def _safe_cowrie_log_event(event: dict[str, Any]) -> dict[str, Any]:
    safe_fields = ["eventid", "timestamp", "src_ip", "session", "input"]
    return _safe_fields(event, safe_fields)


def _safe_high_interaction_event(event: dict[str, Any]) -> dict[str, Any]:
    safe_fields = ["source", "asset_id", "service", "event_type", "attacker_key"]
    return _safe_fields(event, safe_fields)


def _safe_internal_http_event(event: dict[str, Any]) -> dict[str, Any]:
    safe_fields = ["attacker_key", "asset_id", "method", "path", "query_string"]
    return _safe_fields(event, safe_fields)


def _safe_opencanary_log_event(event: dict[str, Any]) -> dict[str, Any]:
    safe_fields = [
        "utc_time",
        "src_host",
        "src_port",
        "dst_host",
        "dst_port",
        "logtype",
    ]
    safe = {
        **_safe_fields(event, safe_fields),
    }
    logdata = event.get("logdata")
    if isinstance(logdata, dict):
        for key, value in logdata.items():
            if key.lower() == "service" and isinstance(value, str):
                safe["service"] = value
    return safe


def _safe_fields(event: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    return {
        field: event[field]
        for field in fields
        if isinstance(event.get(field), (str, int, float, bool))
    }


def _last_forwarder_log_line(container_name: str) -> str:
    if not container_name:
        return ""
    lines = _probe_container_logs(container_name)
    for line in reversed(lines):
        if (
            line.startswith("Forwarded ")
            or line.startswith("Skipped ")
            or "Could not reach" in line
            or "Adapter rejected" in line
            or "Observer rejected" in line
            or "Observer returned" in line
        ):
            return line
    return ""


def _probe_container_logs(container_name: str) -> list[str]:
    try:
        result = subprocess.run(
            ["docker", "logs", "--timestamps", "--tail", "80", container_name],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except Exception:
        return []
    if result.returncode != 0:
        return []
    timestamped_lines = [_split_docker_timestamp(line) for line in result.stdout.splitlines()]
    timestamped_lines = [item for item in timestamped_lines if item[1]]
    timestamped_lines.sort(key=lambda item: item[0])
    return [message for _, message in timestamped_lines]


def _split_docker_timestamp(line: str) -> tuple[str, str]:
    stripped = line.strip()
    if not stripped:
        return "", ""
    timestamp, separator, message = stripped.partition(" ")
    if separator and "T" in timestamp and timestamp.endswith("Z"):
        return timestamp, message.strip()
    return "", stripped
