#!/usr/bin/env python3
"""Run controller ticks for profiles produced by local Cowrie telemetry.

This helper is intentionally small and file-driven. The Cowrie adapter writes
bindings/profiles into `data/runtime/*.json`; this loop reads those files,
asks the controller what should be unlocked next, and asks the orchestrator to
apply those actions. In the local demo this is what turns a Cowrie command such
as `id` into newly exposed Docker-backed asset ports.

Example:
    python scripts/adaptive_controller_loop.py --once
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def read_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    """Read a JSON object, returning `default` when runtime state is absent."""
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        return default
    return payload


def post_json(
    url: str,
    payload: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    """POST JSON to one local service and return the decoded JSON response."""
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8")
    decoded = json.loads(body)
    if not isinstance(decoded, dict):
        raise RuntimeError(f"{url} returned a non-object JSON response")
    return decoded


def load_bindings_by_attacker(state_dir: Path) -> dict[str, dict[str, Any]]:
    """Return latest binding records keyed by attacker_key."""
    payload = read_json(state_dir / "bindings.json", {"records": []})
    records = payload.get("records", [])
    if not isinstance(records, list):
        return {}
    return {
        str(record.get("attacker_key")): record
        for record in records
        if isinstance(record, dict) and record.get("attacker_key")
    }


def load_profiles(state_dir: Path) -> dict[str, dict[str, Any]]:
    """Return latest profile snapshots keyed by attacker_key."""
    payload = read_json(state_dir / "profiles.json", {"profiles": {}})
    profiles = payload.get("profiles", {})
    return profiles if isinstance(profiles, dict) else {}


def tick_once(
    state_dir: Path,
    controller_url: str,
    orchestrator_url: str,
    timeout_seconds: float,
) -> int:
    """Run one adaptive control pass and return number of unlock actions sent."""
    bindings_by_attacker = load_bindings_by_attacker(state_dir)
    profiles = load_profiles(state_dir)
    applied_unlocks = 0

    for attacker_key, profile in profiles.items():
        if not isinstance(profile, dict):
            continue
        binding = bindings_by_attacker.get(attacker_key)
        if binding is None:
            continue

        binding_id = binding.get("binding_id")
        unlocked_assets = binding.get("unlocked_assets", [])
        if not isinstance(binding_id, str):
            continue
        if not isinstance(unlocked_assets, list):
            unlocked_assets = []

        controller_response = post_json(
            f"{controller_url}/v1/controller/tick",
            {
                "attacker_key": attacker_key,
                "binding_id": binding_id,
                "profile": profile,
                "unlocked_asset_ids": unlocked_assets,
            },
            timeout_seconds=timeout_seconds,
        )
        actions = controller_response.get("actions", [])
        if not isinstance(actions, list):
            continue

        unlock_actions = [
            action
            for action in actions
            if isinstance(action, dict) and action.get("action_type") == "unlock"
        ]
        if not unlock_actions:
            continue

        orchestrator_response = post_json(
            f"{orchestrator_url}/v1/orchestration/apply",
            {
                "binding_id": binding_id,
                "actions": actions,
            },
            timeout_seconds=timeout_seconds,
        )
        applied_unlocks += len(unlock_actions)
        print_apply_summary(attacker_key, orchestrator_response)

    return applied_unlocks


def print_apply_summary(
    attacker_key: str,
    response: dict[str, Any],
) -> None:
    """Print only the useful result of an orchestrator apply response."""
    route_updates = response.get("route_updates", [])
    for route_update in route_updates if isinstance(route_updates, list) else []:
        print(f"[adaptive] {attacker_key}: {route_update}", flush=True)

    runtime_events = response.get("runtime_events", [])
    if not isinstance(runtime_events, list):
        return
    for event in runtime_events:
        if not isinstance(event, dict):
            continue
        settings = event.get("settings", {})
        settings = settings if isinstance(settings, dict) else {}
        port_mappings = settings.get("port_mappings", [])
        if isinstance(port_mappings, list) and port_mappings:
            ports = ", ".join(
                _format_port_mapping(mapping)
                for mapping in port_mappings
                if isinstance(mapping, dict)
            )
            print(
                f"[adaptive] opened {event.get('asset_id')} via {settings.get('image')} on {ports}",
                flush=True,
            )
        else:
            print(
                f"[adaptive] enabled {event.get('asset_id')} "
                f"with runtime={settings.get('runtime_backend', 'mock')}",
                flush=True,
            )


def _format_port_mapping(mapping: dict[str, Any]) -> str:
    """Render one runtime port mapping for terminal output."""
    host = mapping.get("host", "127.0.0.1")
    host_port = mapping.get("host_port", "?")
    container_port = mapping.get("container_port", "?")
    return f"{host}:{host_port}->{container_port}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run adaptive controller/orchestrator ticks for local Cowrie profiles.",
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path("data/runtime"),
        help="Directory containing bindings.json and profiles.json.",
    )
    parser.add_argument(
        "--controller-url",
        default="http://127.0.0.1:8003",
        help="Base URL for services.controller.app.",
    )
    parser.add_argument(
        "--orchestrator-url",
        default="http://127.0.0.1:8006",
        help="Base URL for services.orchestrator.app.",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=2.0,
        help="Delay between ticks when running continuously.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=5.0,
        help="HTTP timeout for local service calls.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one tick and exit.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    while True:
        try:
            tick_once(
                state_dir=args.state_dir,
                controller_url=args.controller_url.rstrip("/"),
                orchestrator_url=args.orchestrator_url.rstrip("/"),
                timeout_seconds=args.timeout_seconds,
            )
        except (HTTPError, URLError, TimeoutError, RuntimeError, json.JSONDecodeError) as exc:
            print(f"[adaptive] tick failed: {exc}", file=sys.stderr, flush=True)

        if args.once:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
