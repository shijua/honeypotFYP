#!/usr/bin/env python3
"""Summarize one adaptive Cowrie demo run.

The adaptive demo writes several small runtime JSON files. This script turns
them into a compact report that is easier to bring to a meeting or paste into
notes: observed Cowrie behavior, latest profile, controller decisions, and the
ports/assets opened by the orchestrator.

Example:
    python scripts/summarize_adaptive_demo.py \
      --write-report data/runtime/adaptive_demo_report.json
"""

from __future__ import annotations

import argparse
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
    observations = _list_from_file(state_dir / "cowrie_observations.json", "observations")
    bindings = _list_from_file(state_dir / "bindings.json", "records")
    runtime_records = _list_from_file(state_dir / "asset_runtime.json", "records")
    decision_trace = _list_from_file(state_dir / "decision_trace.json", "records")
    profiles_payload = read_json(state_dir / "profiles.json", {"profiles": {}})
    profiles = profiles_payload.get("profiles", {})
    profiles = profiles if isinstance(profiles, dict) else {}
    docker_probe = current_docker_status()

    attackers = sorted(
        {
            str(item.get("attacker_key"))
            for item in [*observations, *bindings, *decision_trace]
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
                docker_probe=docker_probe,
            )
            for attacker_key in attackers
        ],
    }


def write_report(report: dict[str, Any], path: Path) -> None:
    """Write the adaptive demo report to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def print_summary(report: dict[str, Any]) -> None:
    """Print a short terminal summary of the demo report."""
    attackers = report.get("attackers", [])
    if not attackers:
        print("Adaptive demo summary: no attackers found")
        return

    print(f"Adaptive demo summary: {len(attackers)} attacker(s)")
    for attacker in attackers:
        if not isinstance(attacker, dict):
            continue
        print(f"- attacker {attacker.get('attacker_key')}")
        print(f"  tactics: {', '.join(attacker.get('recent_tactics', [])) or 'none'}")
        print(f"  techniques: {', '.join(attacker.get('recent_techniques', [])) or 'none'}")
        print(f"  commands: {', '.join(attacker.get('commands', [])) or 'none'}")
        docker_probe_error = attacker.get("docker_probe_error")
        current = attacker.get("current_running_assets", [])
        failed = attacker.get("failed_assets", [])
        if isinstance(docker_probe_error, str) and docker_probe_error:
            print(f"  current running assets: unavailable ({docker_probe_error})")
        elif current:
            print("  current running assets:")
            for asset in current:
                if isinstance(asset, dict):
                    ports = ", ".join(asset.get("ports", [])) or "no real port"
                    print(
                        f"    {asset.get('asset_id')} "
                        f"({asset.get('runtime_backend')}): {ports}"
                    )
        else:
            print("  current running assets: none")

        if failed:
            print("  failed assets:")
            for asset in failed:
                if isinstance(asset, dict):
                    detail = asset.get("failure_detail") or asset.get(
                        "current_container_status",
                        "failed",
                    )
                    print(
                        f"    {asset.get('asset_id')} "
                        f"({asset.get('runtime_backend')}): {detail}"
                    )
        else:
            print("  failed assets: none")

        historical = attacker.get("historical_opened_assets", [])
        if historical:
            print("  historical opened assets:")
            for asset in historical:
                if isinstance(asset, dict):
                    ports = ", ".join(asset.get("ports", [])) or "no real port"
                    current = asset.get("current_container_status", "unknown")
                    print(
                        f"    {asset.get('asset_id')} "
                        f"({asset.get('runtime_backend')}, current={current}): {ports}"
                    )
        else:
            print("  historical opened assets: none")


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


def _attacker_report(
    attacker_key: str,
    observations: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
    profiles: dict[str, Any],
    runtime_records: list[dict[str, Any]],
    decision_trace: list[dict[str, Any]],
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

    historical_assets = [
        _runtime_summary(item, docker_probe)
        for item in attacker_runtime
    ]
    current_assets = [
        asset
        for asset in historical_assets
        if asset.get("runtime_backend") == "docker"
        and str(asset.get("current_container_status", "")).startswith("Up")
    ]
    failed_assets = [asset for asset in historical_assets if _asset_summary_is_failed(asset)]

    return {
        "attacker_key": attacker_key,
        "binding_id": binding_id,
        "event_counts": dict(
            sorted(Counter(_eventids(attacker_observations)).items())
        ),
        "commands": _commands(attacker_observations),
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
    return [
        str(item["eventid"])
        for item in observations
        if isinstance(item.get("eventid"), str)
    ]


def _commands(observations: list[dict[str, Any]]) -> list[str]:
    commands = [
        str(item["command"]).strip()
        for item in observations
        if item.get("eventid") == "cowrie.command.input"
        and isinstance(item.get("command"), str)
        and str(item.get("command")).strip()
    ]
    return list(dict.fromkeys(commands))


def _runtime_summary(
    record: dict[str, Any],
    docker_probe: DockerStatusProbe,
) -> dict[str, Any]:
    settings = record.get("settings", {})
    settings = settings if isinstance(settings, dict) else {}
    container_name = settings.get("container_name")
    current_status = "not_applicable"
    if settings.get("runtime_backend") == "docker":
        if docker_probe.error:
            current_status = "unavailable"
        else:
            current_status = docker_probe.statuses.get(str(container_name), "not_found")
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
        "runtime_backend": settings.get("runtime_backend", "mock"),
        "container_name": container_name,
        "current_container_status": current_status,
        "failure_detail": failure_detail,
        "image": settings.get("image"),
        "ports": [_format_port_mapping(item) for item in _port_mappings(settings)],
    }


def _asset_summary_is_failed(asset: dict[str, Any]) -> bool:
    if asset.get("status") == "failed":
        return True
    if asset.get("runtime_backend") != "docker":
        return False
    current_status = str(asset.get("current_container_status", ""))
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


def _port_mappings(settings: dict[str, Any]) -> list[dict[str, Any]]:
    mappings = settings.get("port_mappings", [])
    if not isinstance(mappings, list):
        return []
    return [item for item in mappings if isinstance(item, dict)]


def _format_port_mapping(mapping: dict[str, Any]) -> str:
    host = mapping.get("host", "127.0.0.1")
    host_port = mapping.get("host_port", "?")
    container_port = mapping.get("container_port", "?")
    return f"{host}:{host_port}->{container_port}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize one adaptive Cowrie demo run.",
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path("data/runtime"),
        help="Directory containing adaptive demo runtime JSON files.",
    )
    parser.add_argument(
        "--write-report",
        type=Path,
        default=None,
        help="Optional JSON report output path.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = summarize_demo(args.state_dir)
    print_summary(report)
    if args.write_report is not None:
        write_report(report, args.write_report)
        print(f"Wrote report: {args.write_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
