#!/usr/bin/env python3
"""Verify controller-selected assets become concrete asset-gateway routes.

This is the route-level evaluation companion to `reveal_policy.py`. In
`controller-only` mode it checks whether a scripted attacker profile selects the
expected assets. In `live-apply` mode it also calls the running control-plane
services, applies controller reveal actions, and verifies exact
`attacker_key + asset_id + public_port` routes in `asset_gateway_routes.json`.

Example:
    python scripts/evaluation/reveal_port_simulation.py --mode live-apply --scenario-file tests/fixtures/reveal_port_scenarios.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from libs.common.config import RuntimeConfig
from libs.common.json_utils import read_json_object
from libs.contracts.models import ActionType, ControllerTickRequest
from scripts.evaluation.charts import write_reveal_port_chart
from scripts.evaluation.reveal_policy import load_scenarios, scenario_request, string_list
from services.controller.domain import ControllerService
from services.controller.repository import FileAssetRepository, FileAttackGroupTechniquePriorRepository

Mode = Literal["controller-only", "live-apply"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Simulate attacker profiles and verify expected asset-gateway ports.")
    parser.add_argument("--mode", choices=("controller-only", "live-apply"), default="controller-only")
    parser.add_argument("--scenario-file", type=Path, default=Path("tests/fixtures/reveal_port_scenarios.json"))
    parser.add_argument("--catalog", type=Path, default=Path("data/assets/catalog.json"))
    parser.add_argument("--prior", type=Path, default=Path("data/technique_prior/attack_group_technique_prior.json"))
    parser.add_argument("--route-file", type=Path, default=Path("data/runtime/asset_gateway_routes.json"))
    parser.add_argument("--output", type=Path, default=Path("data/runtime/reveal_port_simulation_report.json"))
    parser.add_argument("--project-name", default="honeynet")
    args = parser.parse_args()

    report = evaluate_reveal_ports(
        mode=args.mode,
        scenario_file=args.scenario_file,
        catalog_path=args.catalog,
        prior_path=args.prior,
        route_path=args.route_file,
        project_name=args.project_name,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{text}\n", encoding="utf-8")
        write_reveal_port_chart(report, args.output.with_suffix(".svg"))
    print(text)
    return 0 if report["ok"] else 1


def evaluate_reveal_ports(
    *,
    mode: Mode,
    scenario_file: Path,
    catalog_path: Path,
    prior_path: Path,
    route_path: Path,
    project_name: str = "honeynet",
    control_client: "ControlPlaneClient | None" = None,
) -> dict[str, Any]:
    """Evaluate all port scenarios and return a pass/fail report.

    Example:
        evaluate_reveal_ports(mode="controller-only", ... )["summary"]["failed"] -> 0
    """
    scenarios = validate_scenarios(load_scenarios(scenario_file))
    client = control_client or DockerControlPlaneClient(project_name)
    rows = [
        evaluate_reveal_port_scenario(
            scenario,
            mode=mode,
            catalog_path=catalog_path,
            prior_path=prior_path,
            route_path=route_path,
            control_client=client,
        )
        for scenario in scenarios
    ]
    failed = sum(1 for row in rows if not row["ok"])
    return {
        "schema_version": "v1",
        "ok": failed == 0,
        "mode": mode,
        "scenario_file": str(scenario_file),
        "summary": {
            "scenario_count": len(rows),
            "passed": len(rows) - failed,
            "failed": failed,
        },
        "scenarios": rows,
    }


def validate_scenarios(scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate required JSON fields before a long live run starts.

    Example:
        missing expected_routes -> ValueError("scenario s1 missing expected_routes").
    """
    for index, scenario in enumerate(scenarios, start=1):
        scenario_id = scenario.get("scenario_id", f"#{index}")
        if not isinstance(scenario.get("scenario_id"), str) or not scenario["scenario_id"]:
            raise ValueError(f"scenario {index} missing scenario_id")
        if "profile" not in scenario and "evidence_sequence" not in scenario:
            raise ValueError(f"scenario {scenario_id} missing profile or evidence_sequence")
        if not string_list(scenario.get("expected_assets")):
            raise ValueError(f"scenario {scenario_id} missing expected_assets")
        routes = scenario.get("expected_routes")
        if not isinstance(routes, list) or not routes:
            raise ValueError(f"scenario {scenario_id} missing expected_routes")
        for route in routes:
            if not isinstance(route, dict) or not isinstance(route.get("asset_id"), str) or not isinstance(route.get("public_port"), int):
                raise ValueError(f"scenario {scenario_id} has invalid expected route {route!r}")
    return scenarios


def evaluate_reveal_port_scenario(
    scenario: dict[str, Any],
    *,
    mode: Mode,
    catalog_path: Path,
    prior_path: Path,
    route_path: Path,
    control_client: "ControlPlaneClient",
) -> dict[str, Any]:
    """Evaluate one scenario in controller-only or live-apply mode."""
    if mode == "controller-only":
        response = _controller_tick(scenario_request(scenario), catalog_path, prior_path)
        selected_assets = _selected_assets(response)
        actual_routes: list[dict[str, Any]] = []
        gateway_state: dict[str, Any] = {}
        runtime_failure = None
    else:
        live_result = _live_apply_scenario(
            scenario,
            catalog_path=catalog_path,
            prior_path=prior_path,
            route_path=route_path,
            control_client=control_client,
        )
        response = live_result["controller_response"]
        selected_assets = live_result["selected_assets"]
        actual_routes = live_result["actual_routes"]
        gateway_state = live_result["gateway_state"]
        runtime_failure = live_result["runtime_failure"]

    expected_assets = string_list(scenario.get("expected_assets"))
    forbidden_assets = string_list(scenario.get("forbidden_assets"))
    expected_routes = _expected_routes(scenario)
    decision_details = _decision_details(response)
    selected_failures = _asset_selection_failures(selected_assets, expected_assets, forbidden_assets)
    route_failures = [] if mode == "controller-only" else _route_failures(actual_routes, expected_routes)
    rejected_runtime_failure = _runtime_rejected_failure(decision_details, expected_assets)
    failure_reason = runtime_failure or rejected_runtime_failure or _first_failure(selected_failures, route_failures)
    ok = failure_reason is None
    return {
        "scenario_id": scenario["scenario_id"],
        "ok": ok,
        "mode": mode,
        "selected_assets": selected_assets,
        "expected_assets": expected_assets,
        "forbidden_assets": forbidden_assets,
        "expected_routes": expected_routes,
        "actual_routes": actual_routes,
        "gateway_state": gateway_state,
        "decision_details": decision_details,
        "failure_reason": failure_reason,
        "selection_failures": selected_failures,
        "route_failures": route_failures,
    }


def _controller_tick(
    request: ControllerTickRequest,
    catalog_path: Path,
    prior_path: Path,
) -> dict[str, Any]:
    service = ControllerService(
        FileAssetRepository(catalog_path),
        FileAttackGroupTechniquePriorRepository(prior_path),
        config=RuntimeConfig(),
    )
    return service.tick(request).model_dump(mode="json")


def _live_apply_scenario(
    scenario: dict[str, Any],
    *,
    catalog_path: Path,
    prior_path: Path,
    route_path: Path,
    control_client: "ControlPlaneClient",
) -> dict[str, Any]:
    attacker_key = str(scenario.get("attacker_key") or f"198.51.100.{200 + abs(hash(scenario['scenario_id'])) % 40}")
    binding = control_client.post_json(
        "binding-service:8001",
        "/v1/bindings/resolve",
        {"attacker_key": attacker_key, "protocol": "tcp"},
    )
    binding_id = str(binding["binding_id"])
    initial_assets = string_list(scenario.get("initial_unlocked_assets"))
    if initial_assets:
        seed_response = _apply_unlocks(control_client, binding_id, initial_assets, reason="port simulation seed unlock")
        binding = seed_response.get("binding", binding)

    request = scenario_request({**scenario, "attacker_key": attacker_key})
    request_payload = request.model_dump(mode="json")
    request_payload["binding_id"] = binding_id
    request_payload["unlocked_asset_ids"] = binding.get("unlocked_assets", initial_assets)
    controller_response = control_client.post_json("controller:8003", "/v1/controller/tick", request_payload)
    reveal_actions = [
        action
        for action in controller_response.get("actions", [])
        if isinstance(action, dict)
        and action.get("action_type") in {ActionType.unlock.value, ActionType.configure.value}
    ]
    apply_response = {"binding": binding, "runtime_events": [], "route_updates": []}
    if reveal_actions:
        apply_response = control_client.post_json(
            "orchestrator:8005",
            "/v1/orchestration/apply",
            {"binding_id": binding_id, "actions": reveal_actions},
        )
    gateway_state = control_client.get_json("gateway:8004", f"/v1/gateway/bindings/{binding_id}")
    all_routes = _load_route_items(route_path)
    actual_routes = matching_expected_routes(
        all_routes,
        attacker_key=attacker_key,
        expected_routes=_expected_routes(scenario),
    )
    return {
        "controller_response": controller_response,
        "selected_assets": _selected_assets(controller_response),
        "actual_routes": actual_routes,
        "gateway_state": gateway_state,
        "runtime_failure": _runtime_failure_reason(apply_response, _expected_assets_set(scenario)),
    }


def matching_expected_routes(
    routes: list[dict[str, Any]],
    *,
    attacker_key: str,
    expected_routes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return latest exact routes for each expected asset/port pair.

    Example:
        two 18081 routes for same attacker -> only the newest matching route is returned.
    """
    matches: list[dict[str, Any]] = []
    for expected in expected_routes:
        asset_id = expected["asset_id"]
        public_port = expected["public_port"]
        route = latest_route_for_attacker_port(routes, attacker_key=attacker_key, public_port=public_port)
        if route is not None and route.get("asset_id") == asset_id:
            matches.append(_route_summary(route))
    return matches


def latest_route_for_attacker_port(
    routes: list[dict[str, Any]],
    *,
    attacker_key: str,
    public_port: int,
) -> dict[str, Any] | None:
    """Return the latest route for one attacker and fixed public port."""
    candidates = [
        route
        for route in routes
        if route.get("attacker_key") == attacker_key and route.get("public_port") == public_port
    ]
    return sorted(candidates, key=lambda route: str(route.get("updated_at", "")))[-1] if candidates else None


def _apply_unlocks(
    control_client: "ControlPlaneClient",
    binding_id: str,
    asset_ids: list[str],
    *,
    reason: str,
) -> dict[str, Any]:
    return control_client.post_json(
        "orchestrator:8005",
        "/v1/orchestration/apply",
        {
            "binding_id": binding_id,
            "actions": [
                {
                    "action_type": ActionType.unlock.value,
                    "binding_id": binding_id,
                    "asset_id": asset_id,
                    "reason": reason,
                }
                for asset_id in asset_ids
            ],
        },
    )


def _load_route_items(path: Path) -> list[dict[str, Any]]:
    payload = read_json_object(path, {"routes": []})
    routes = payload.get("routes", []) if isinstance(payload, dict) else []
    return [route for route in routes if isinstance(route, dict)] if isinstance(routes, list) else []


def _selected_assets(controller_response: dict[str, Any]) -> list[str]:
    selected: list[str] = []
    for action in controller_response.get("actions", []):
        if not isinstance(action, dict):
            continue
        if action.get("action_type") == ActionType.unlock.value and isinstance(action.get("asset_id"), str):
            selected.append(str(action["asset_id"]))
        if action.get("action_type") == ActionType.configure.value:
            exposed_asset = action.get("target_asset_id") or action.get("asset_id")
            if isinstance(exposed_asset, str):
                selected.append(exposed_asset)
    return selected


def _decision_details(controller_response: dict[str, Any]) -> list[dict[str, Any]]:
    details = []
    for event in controller_response.get("decision_events", []):
        if isinstance(event, dict) and isinstance(event.get("details"), dict):
            details.append(event["details"])
    return details


def _asset_selection_failures(
    selected_assets: list[str],
    expected_assets: list[str],
    forbidden_assets: list[str],
) -> list[str]:
    failures = [f"missing expected asset {asset_id}" for asset_id in expected_assets if asset_id not in selected_assets]
    failures.extend(f"selected forbidden asset {asset_id}" for asset_id in forbidden_assets if asset_id in selected_assets)
    return failures


def _route_failures(
    actual_routes: list[dict[str, Any]],
    expected_routes: list[dict[str, Any]],
) -> list[str]:
    failures = []
    for expected in expected_routes:
        if not any(route.get("asset_id") == expected["asset_id"] and route.get("public_port") == expected["public_port"] for route in actual_routes):
            failures.append(f"missing route {expected['asset_id']}:{expected['public_port']}")
    return failures


def _runtime_failure_reason(
    apply_response: dict[str, Any],
    expected_assets: set[str],
) -> str | None:
    for event in apply_response.get("runtime_events", []):
        if not isinstance(event, dict) or event.get("asset_id") not in expected_assets:
            continue
        if str(event.get("status", "")).lower() in {"failed", "missing", "unavailable"}:
            return f"failed_runtime_unavailable: {event.get('asset_id')}"
    return None


def _runtime_rejected_failure(
    decision_details: list[dict[str, Any]],
    expected_assets: list[str],
) -> str | None:
    """Return a clear failure when controller rejected an expected runtime asset.

    Example:
        rejected_assets={"dionaea-capture": "runtime unavailable on this host"}
        -> "failed_runtime_unavailable: dionaea-capture".
    """
    for details in decision_details:
        rejected = details.get("rejected_assets", {})
        if not isinstance(rejected, dict):
            continue
        for asset_id in expected_assets:
            reason = rejected.get(asset_id)
            if isinstance(reason, str) and "runtime unavailable" in reason:
                return f"failed_runtime_unavailable: {asset_id}"
    return None


def _first_failure(*groups: list[str]) -> str | None:
    for group in groups:
        if group:
            return group[0]
    return None


def _expected_routes(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    routes = scenario.get("expected_routes", [])
    return [
        {"asset_id": str(route["asset_id"]), "public_port": int(route["public_port"])}
        for route in routes
        if isinstance(route, dict) and isinstance(route.get("asset_id"), str) and isinstance(route.get("public_port"), int)
    ]


def _expected_assets_set(scenario: dict[str, Any]) -> set[str]:
    return set(string_list(scenario.get("expected_assets")))


def _route_summary(route: dict[str, Any]) -> dict[str, Any]:
    keys = ("attacker_key", "binding_id", "asset_id", "public_port", "backend_host", "backend_port", "updated_at")
    return {key: route.get(key) for key in keys if key in route}


class ControlPlaneClient:
    """HTTP client interface used by live-apply mode."""

    def post_json(self, host: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def get_json(self, host: str, path: str) -> dict[str, Any]:
        raise NotImplementedError


class DockerControlPlaneClient(ControlPlaneClient):
    """Call compose-internal APIs through an ephemeral curl container.

    Example:
        DockerControlPlaneClient("honeynet").post_json("controller:8003", "/v1/controller/tick", payload)
    """

    def __init__(self, project_name: str) -> None:
        self._network = f"{project_name}_net_control"

    def post_json(self, host: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request_json("POST", host, path, payload)

    def get_json(self, host: str, path: str) -> dict[str, Any]:
        return self._request_json("GET", host, path, None)

    def _request_json(
        self,
        method: Literal["GET", "POST"],
        host: str,
        path: str,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        command = [
            "docker",
            "run",
            "--rm",
            "-i",
            "--network",
            self._network,
            "curlimages/curl:latest",
            "-fsS",
            "-H",
            "Content-Type: application/json",
        ]
        if method == "POST":
            command.extend(["--data-binary", "@-"])
        command.append(f"http://{host}{path}")
        result = subprocess.run(
            command,
            input=json.dumps(payload or {}).encode("utf-8") if method == "POST" else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip())
        decoded = json.loads(result.stdout.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise RuntimeError(f"{host}{path} returned non-object JSON")
        return decoded


if __name__ == "__main__":
    raise SystemExit(main())
