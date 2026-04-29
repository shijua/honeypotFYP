"""Build dashboard summaries from runtime JSON state."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Any


@dataclass(frozen=True)
class DockerStatusProbe:
    """Result of asking Docker which honeynet containers currently exist."""

    statuses: dict[str, str]
    error: str | None = None


def read_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    """Read a JSON object from disk, returning default when the file is absent."""
    if not path.exists():
        return default
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else default


def summarize_demo(state_dir: Path) -> dict[str, Any]:
    """Build a deterministic report from adaptive demo runtime files."""
    cowrie_observations = _list_from_file(
        state_dir / "cowrie_observations.json",
        "observations",
    )
    entrypoint_observations = _list_from_file(
        state_dir / "entrypoint_observations.json",
        "observations",
    )
    opencanary_observations = _list_from_file(
        state_dir / "opencanary_observations.json",
        "observations",
    )
    observations = [
        *entrypoint_observations,
        *cowrie_observations,
        *opencanary_observations,
    ]
    bindings = _list_from_file(state_dir / "bindings.json", "records")
    runtime_records = _list_from_file(state_dir / "asset_runtime.json", "records")
    decision_trace = _list_from_file(state_dir / "decision_trace.json", "records")
    evidence_records = _evidence_records(state_dir / "evidence.json")
    profiles_payload = read_json(state_dir / "profiles.json", {"profiles": {}})
    profiles = profiles_payload.get("profiles", {})
    profiles = profiles if isinstance(profiles, dict) else {}
    docker_probe = current_docker_status()

    attackers = sorted(
        {
            str(item.get("attacker_key"))
            for item in [*observations, *bindings, *decision_trace, *evidence_records]
            if isinstance(item, dict) and item.get("attacker_key")
        }
    )

    return {
        "schema_version": "v1",
        "state_dir": str(state_dir),
        "attackers": [
            _attacker_report(
                attacker_key=attacker_key,
                observations=observations,
                bindings=bindings,
                profiles=profiles,
                runtime_records=runtime_records,
                decision_trace=decision_trace,
                evidence_records=evidence_records,
                docker_probe=docker_probe,
            )
            for attacker_key in attackers
        ],
    }


def current_docker_status() -> DockerStatusProbe:
    """Return current Docker status for honeynet containers when available.

    Reports should distinguish historical runtime records from containers that
    still exist in `docker ps`. Docker may be unavailable during tests or on a
    documentation-only machine, so failures produce an empty map.
    """
    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                "label=honeynet.mvp=true",
                "--format",
                "{{.Names}}\t{{.Status}}",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        return DockerStatusProbe(statuses={}, error=str(exc))
    if result.returncode != 0:
        return DockerStatusProbe(
            statuses={},
            error=result.stderr.strip() or f"docker ps failed with code {result.returncode}",
        )
    statuses: dict[str, str] = {}
    for line in result.stdout.splitlines():
        name, separator, status = line.partition("\t")
        if separator and name:
            statuses[name] = status
    return DockerStatusProbe(statuses=statuses, error=None)


def _list_from_file(path: Path, key: str) -> list[dict[str, Any]]:
    payload = read_json(path, {key: []})
    items = payload.get(key, [])
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _evidence_records(path: Path) -> list[dict[str, Any]]:
    payload = read_json(path, {"records": {}})
    records = payload.get("records", {})
    if not isinstance(records, dict):
        return []
    items: list[dict[str, Any]] = []
    for attacker_key, attacker_records in records.items():
        if not isinstance(attacker_records, list):
            continue
        for item in attacker_records:
            if not isinstance(item, dict):
                continue
            item = dict(item)
            item.setdefault("attacker_key", str(attacker_key))
            items.append(item)
    return items


def _attacker_report(
    attacker_key: str,
    observations: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
    profiles: dict[str, Any],
    runtime_records: list[dict[str, Any]],
    decision_trace: list[dict[str, Any]],
    evidence_records: list[dict[str, Any]],
    docker_probe: DockerStatusProbe,
) -> dict[str, Any]:
    attacker_observations = [
        item for item in observations if item.get("attacker_key") == attacker_key
    ]
    binding = _latest_binding(attacker_key, bindings)
    binding_id = binding.get("binding_id") if binding else None
    profile = profiles.get(attacker_key, {})
    profile = profile if isinstance(profile, dict) else {}
    attacker_runtime = [
        item for item in runtime_records if item.get("binding_id") == binding_id
    ]
    attacker_trace = [
        item for item in decision_trace if item.get("attacker_key") == attacker_key
    ]
    attacker_evidence = [
        item for item in evidence_records if item.get("attacker_key") == attacker_key
    ]

    historical_assets = [
        _runtime_summary(item, docker_probe)
        for item in attacker_runtime
    ]
    current_assets = [
        asset
        for asset in historical_assets
        if asset.get("runtime_backend") in {"docker", "compose"}
        and str(asset.get("current_container_status", "")).startswith("Up")
        and not _asset_summary_is_failed(asset)
    ]
    failed_assets = [asset for asset in historical_assets if _asset_summary_is_failed(asset)]

    return {
        "attacker_key": attacker_key,
        "binding_id": binding_id,
        "event_counts": dict(
            sorted(Counter(_eventids(attacker_observations)).items())
        ),
        "commands": _commands(attacker_observations),
        "public_http_evidence": _public_http_evidence(attacker_evidence),
        "recent_tactics": profile.get("recent_tactics", []),
        "recent_techniques": profile.get("recent_techniques", []),
        "confidence_by_tactic": profile.get("conf_by_tactic", {}),
        "docker_probe_error": docker_probe.error,
        "unlocked_assets": binding.get("unlocked_assets", []) if binding else [],
        "historical_opened_assets": historical_assets,
        "current_running_assets": current_assets,
        "failed_assets": failed_assets,
        "decisions": [_decision_summary(item) for item in attacker_trace],
    }


def _latest_binding(
    attacker_key: str,
    bindings: list[dict[str, Any]],
) -> dict[str, Any] | None:
    matches = [item for item in bindings if item.get("attacker_key") == attacker_key]
    if not matches:
        return None
    return sorted(matches, key=lambda item: str(item.get("last_seen_ts", "")))[-1]


def _eventids(observations: list[dict[str, Any]]) -> list[str]:
    eventids: list[str] = []
    for item in observations:
        if isinstance(item.get("eventid"), str):
            eventids.append(str(item["eventid"]))
            continue
        if isinstance(item.get("service"), str):
            eventids.append(f"opencanary.{item['service']}")
            continue
        if isinstance(item.get("method"), str) and isinstance(item.get("path"), str):
            eventids.append(f"public_http.{str(item['method']).upper()}")
    return eventids


def _commands(observations: list[dict[str, Any]]) -> list[str]:
    commands = [
        str(item["command"]).strip()
        for item in observations
        if item.get("eventid") == "cowrie.command.input"
        and isinstance(item.get("command"), str)
        and str(item.get("command")).strip()
    ]
    return list(dict.fromkeys(commands))


def _public_http_evidence(evidences: list[dict[str, Any]]) -> list[str]:
    """Return concise public HTTP evidence for the attacker card."""
    evidence: list[str] = []
    for item in evidences:
        source_ref = item.get("source_ref")
        if not isinstance(source_ref, dict):
            continue
        if source_ref.get("source") != "public_http":
            continue
        labels = source_ref.get("http_evidence_labels")
        indicators = source_ref.get("http_indicators")
        http_path = source_ref.get("http_path")
        http_query = source_ref.get("http_query_string")
        http_user_agent = source_ref.get("http_user_agent")
        if isinstance(labels, list):
            evidence.extend(
                f"rule:{label.strip()}"
                for label in labels
                if isinstance(label, str) and label.strip()
            )
        if isinstance(indicators, list):
            evidence.extend(
                str(indicator).strip()
                for indicator in indicators
                if str(indicator).strip()
            )
        if isinstance(http_path, str) and http_path.strip():
            target = http_path.strip()
            if isinstance(http_query, str) and http_query.strip():
                target = f"{target}?{http_query.strip()}"
            evidence.append(f"path:{target}")
        if isinstance(http_user_agent, str) and http_user_agent.strip():
            evidence.append(f"ua:{http_user_agent.strip()}")
    return list(dict.fromkeys(evidence))


def _runtime_summary(
    record: dict[str, Any],
    docker_probe: DockerStatusProbe,
) -> dict[str, Any]:
    settings = record.get("settings", {})
    settings = settings if isinstance(settings, dict) else {}
    runtime_backend = settings.get("runtime_backend", "mock")
    container_name = settings.get("container_name")
    compose_project = settings.get("compose_project")
    current_status = "not_applicable"
    live_container_statuses: dict[str, str] = {}
    container_names: list[str] = []
    if isinstance(settings.get("container_names"), list):
        container_names = [str(name) for name in settings.get("container_names", []) if name]
    if runtime_backend == "docker":
        if docker_probe.error:
            current_status = "unavailable"
        else:
            current_status = docker_probe.statuses.get(str(container_name), "not_found")
    elif runtime_backend == "compose":
        if docker_probe.error:
            current_status = "unavailable"
        elif isinstance(compose_project, str) and compose_project:
            compose_statuses = _current_compose_statuses(compose_project)
            if compose_statuses:
                live_container_statuses = compose_statuses
                container_names = list(compose_statuses.keys())
                current_status = "; ".join(compose_statuses.values())
            else:
                current_status = "not_found"
        else:
            current_status = "unknown"
    failure_detail = ""
    if isinstance(settings.get("runtime_failure"), str) and settings.get("runtime_failure"):
        failure_detail = str(settings.get("runtime_failure"))
    elif current_status not in {"unknown", "unavailable"} and not str(current_status).startswith("Up"):
        failure_detail = str(current_status)
    return {
        "asset_id": record.get("asset_id"),
        "asset_name": record.get("asset_name"),
        "status": record.get("status"),
        "template_family": record.get("template_family"),
        "runtime_backend": runtime_backend,
        "container_name": container_name,
        "container_names": container_names,
        "container_statuses": live_container_statuses,
        "compose_project": compose_project,
        "current_container_status": current_status,
        "failure_detail": failure_detail,
        "image": settings.get("image"),
        "ports": [_format_port_mapping(item) for item in _port_mappings(settings)],
    }


def _asset_summary_is_failed(asset: dict[str, Any]) -> bool:
    if asset.get("status") == "failed":
        return True
    if asset.get("runtime_backend") not in {"docker", "compose"}:
        return False
    current_status = str(asset.get("current_container_status", ""))
    container_statuses = asset.get("container_statuses", {})
    if asset.get("runtime_backend") == "compose" and isinstance(container_statuses, dict):
        statuses = [str(status) for status in container_statuses.values()]
        return not statuses or any(not status.startswith("Up") for status in statuses)
    return bool(current_status) and current_status not in {"unknown", "unavailable"} and not current_status.startswith("Up")


def _decision_summary(record: dict[str, Any]) -> dict[str, Any]:
    actions = record.get("actions", [])
    actions = actions if isinstance(actions, list) else []
    dropped_actions = record.get("dropped_actions", [])
    dropped_actions = dropped_actions if isinstance(dropped_actions, list) else []
    decision_events = record.get("decision_events", [])
    decision_events = decision_events if isinstance(decision_events, list) else []
    return {
        "ts": record.get("ts"),
        "recent_tactics": record.get("recent_tactics", []),
        "candidate_asset_ids": record.get("candidate_asset_ids", []),
        "action_asset_ids": [
            action.get("asset_id")
            for action in actions
            if isinstance(action, dict) and action.get("action_type") == "unlock"
        ],
        "dropped_action_asset_ids": [
            action.get("asset_id")
            for action in dropped_actions
            if isinstance(action, dict) and action.get("action_type") == "unlock"
        ],
        "reasons": [
            event.get("reason")
            for event in decision_events
            if isinstance(event, dict) and event.get("reason")
        ],
        "route_updates": record.get("route_updates", []),
        "runtime_events": record.get("runtime_events", []),
    }


def _current_compose_statuses(compose_project: str) -> dict[str, str]:
    """Return live container statuses for one Compose-backed asset project."""
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={compose_project}",
            "--format",
            "{{.Names}}\t{{.Status}}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return {}
    statuses: dict[str, str] = {}
    for line in result.stdout.splitlines():
        name, separator, status = line.partition("\t")
        if separator and name:
            statuses[name] = status
    return statuses


def _port_mappings(settings: dict[str, Any]) -> list[dict[str, Any]]:
    mappings = settings.get("port_mappings", [])
    if not isinstance(mappings, list):
        return []
    return [item for item in mappings if isinstance(item, dict)]


def _format_port_mapping(mapping: dict[str, Any]) -> str:
    host = mapping.get("host", "127.0.0.1")
    host_port = mapping.get("host_port", "?")
    container_port = mapping.get("container_port", "?")
    backend_host = mapping.get("backend_host")
    backend_port = mapping.get("backend_port", container_port)
    if backend_host:
        return f"gateway {host}:{host_port}->{backend_host}:{backend_port}"
    return f"{host}:{host_port}->{container_port}"
