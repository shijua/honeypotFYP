#!/usr/bin/env python3
"""Run controller ticks for profiles produced by local Cowrie telemetry.

This helper is intentionally small and file-driven. The Cowrie adapter writes
bindings/profiles into `data/runtime/*.json`; this loop reads those files,
asks the controller what should be unlocked next, and asks the orchestrator to
apply those actions. In the local demo this is what turns a Cowrie command such
as `id` into newly exposed Docker-backed asset ports.

Example:
    python scripts/runtime/adaptive_controller_loop.py --once
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from libs.common.clock import parse_iso_datetime
from libs.common.iterables import dedupe_preserve
from libs.common.iterables import string_items
from libs.common.json_utils import mutable_nested_dict
from libs.common.json_utils import read_json_object
from libs.common.runtime_records import evidence_records as evidence_records_from_file
from services.controller.repository import FileRevealFeedbackRepository


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
    payload = read_json_object(state_dir / "bindings.json", {"records": []})
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
    payload = read_json_object(state_dir / "profiles.json", {"profiles": {}})
    profiles = payload.get("profiles", {})
    return profiles if isinstance(profiles, dict) else {}


def load_loop_state(path: Path) -> dict[str, Any]:
    """Load loop progress so the same evidence does not reopen more assets."""
    return read_json_object(path, {"processed_evidence_ids_by_attacker": {}})


def save_loop_state(path: Path, state: dict[str, Any]) -> None:
    """Persist loop progress after an attacker profile has been processed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")


def tick_once(
    state_dir: Path,
    controller_url: str,
    orchestrator_url: str,
    timeout_seconds: float,
    trace_file: Path | None = None,
    loop_state_file: Path | None = None,
    feedback_file: Path | None = None,
    feedback_window_seconds: int = 300,
    max_actions_per_trigger: int = 2,
) -> int:
    """Run one adaptive control pass and return number of reveal actions sent."""
    bindings_by_attacker = load_bindings_by_attacker(state_dir)
    profiles = load_profiles(state_dir)
    if feedback_file is not None:
        update_reveal_feedback_from_evidence(
            feedback_file=feedback_file,
            evidence_file=state_dir / "evidence.json",
            internal_http_events_file=state_dir / "internal_http_events.jsonl",
            feedback_window_seconds=feedback_window_seconds,
        )
    loop_state = (
        load_loop_state(loop_state_file)
        if loop_state_file is not None
        else {"processed_evidence_ids_by_attacker": {}}
    )
    applied_reveals = 0

    for attacker_key, profile in profiles.items():
        if not isinstance(profile, dict):
            continue
        recent_evidence_ids = string_items(profile.get("recent_evidence_ids", []))
        if loop_state_file is not None and not _has_new_evidence(
            loop_state,
            attacker_key,
            recent_evidence_ids,
        ):
            continue

        binding = bindings_by_attacker.get(attacker_key)
        if binding is None:
            continue

        binding_inputs = _binding_runtime_inputs(binding)
        if binding_inputs is None:
            continue
        binding_id, unlocked_assets, revealed_configurations = binding_inputs

        # Response gate: after the first reveal, runtime must observe the
        # attacker touching the most recent revealed asset/config before asking
        # the controller to open another one. This keeps the live loop as
        # reveal -> observe response -> next reveal, instead of continuously
        # expanding exposure on unrelated profile changes.
        if feedback_file is not None:
            gate_decision = response_gate_decision(
                feedback_file=feedback_file,
                attacker_key=attacker_key,
                binding_id=binding_id,
                profile=profile,
            )
            if not gate_decision["allowed"]:
                _finish_without_apply(
                    trace_file=trace_file,
                    loop_state_file=loop_state_file,
                    loop_state=loop_state,
                    attacker_key=attacker_key,
                    binding=binding,
                    profile=profile,
                    recent_evidence_ids=recent_evidence_ids,
                    controller_response=_response_gate_controller_response(gate_decision),
                )
                continue

        controller_response = post_json(
            f"{controller_url}/v1/controller/tick",
            {
                "attacker_key": attacker_key,
                "binding_id": binding_id,
                "profile": profile,
                "unlocked_asset_ids": unlocked_assets,
                "revealed_configurations": revealed_configurations,
            },
            timeout_seconds=timeout_seconds,
        )
        actions = controller_response.get("actions", [])
        if not isinstance(actions, list):
            continue

        reveal_actions = _reveal_actions(actions)
        if not reveal_actions:
            _finish_without_apply(
                trace_file=trace_file,
                loop_state_file=loop_state_file,
                loop_state=loop_state,
                attacker_key=attacker_key,
                binding=binding,
                profile=profile,
                recent_evidence_ids=recent_evidence_ids,
                controller_response={
                    **controller_response,
                    "actions": actions,
                    "dropped_actions": [],
                },
            )
            continue

        actions_to_apply = _limit_reveal_actions(actions, max_actions_per_trigger)
        applied_reveal_actions = _reveal_actions(actions_to_apply)
        orchestrator_response = post_json(
            f"{orchestrator_url}/v1/orchestration/apply",
            {
                "binding_id": binding_id,
                "actions": actions_to_apply,
            },
            timeout_seconds=timeout_seconds,
        )
        if feedback_file is not None:
            record_reveal_feedback(
                feedback_file=feedback_file,
                attacker_key=attacker_key,
                binding_id=binding_id,
                controller_response=controller_response,
                applied_actions=applied_reveal_actions,
            )
        applied_reveals += len(applied_reveal_actions)
        if trace_file is not None:
            append_trace_record(
                trace_file,
                build_trace_record(
                    attacker_key=attacker_key,
                    binding=binding,
                    profile=profile,
                    controller_response={
                        **controller_response,
                        "actions": actions_to_apply,
                        "dropped_actions": _dropped_actions(actions, actions_to_apply),
                    },
                    orchestrator_response=orchestrator_response,
                ),
            )
        _mark_evidence_processed(loop_state, attacker_key, recent_evidence_ids)
        if loop_state_file is not None:
            save_loop_state(loop_state_file, loop_state)
        print_apply_summary(attacker_key, orchestrator_response)

    return applied_reveals


def _binding_runtime_inputs(binding: dict[str, Any]) -> tuple[str, list[Any], dict[str, Any]] | None:
    """Return validated binding fields needed by the controller request."""
    binding_id = binding.get("binding_id")
    if not isinstance(binding_id, str):
        return None
    unlocked_assets = binding.get("unlocked_assets", [])
    revealed_configurations = binding.get("revealed_configurations", {})
    if not isinstance(unlocked_assets, list):
        unlocked_assets = []
    if not isinstance(revealed_configurations, dict):
        revealed_configurations = {}
    return binding_id, unlocked_assets, revealed_configurations


def _finish_without_apply(
    *,
    trace_file: Path | None,
    loop_state_file: Path | None,
    loop_state: dict[str, Any],
    attacker_key: str,
    binding: dict[str, Any],
    profile: dict[str, Any],
    recent_evidence_ids: list[str],
    controller_response: dict[str, Any],
) -> None:
    """Write a no-apply trace and mark evidence processed."""
    if trace_file is not None:
        append_trace_record(
            trace_file,
            build_trace_record(
                attacker_key=attacker_key,
                binding=binding,
                profile=profile,
                controller_response=controller_response,
                orchestrator_response=_no_apply_orchestrator_response(binding),
            ),
        )
    _mark_evidence_processed(loop_state, attacker_key, recent_evidence_ids)
    if loop_state_file is not None:
        save_loop_state(loop_state_file, loop_state)


def response_gate_decision(
    *,
    feedback_file: Path,
    attacker_key: str,
    binding_id: str,
    profile: dict[str, Any],
) -> dict[str, Any]:
    """Decide whether this binding may ask the controller for another reveal.

    The first reveal is always allowed. After that, the latest reveal batch must
    receive a response before the loop continues. A response is either:

    - useful/shallow feedback resolved from later evidence; or
    - a recent profile asset touch that names one of the revealed assets.

    Ignored reveals remain blocking because they mean the previous exposure did
    not receive a response within the feedback window.
    """
    payload = read_json_object(feedback_file, {"pending": []})
    records = _feedback_records_for_binding(payload, attacker_key, binding_id)
    if not records:
        return {
            "allowed": True,
            "reason": "no previous reveal",
            "binding_id": binding_id,
            "attacker_key": attacker_key,
        }

    latest = _latest_feedback_record(records)
    latest_assets = _feedback_revealed_assets(latest)
    batch = _latest_reveal_batch(records, latest, latest_assets)
    statuses = {
        str(item.get("asset_id")): str(item.get("status", "pending"))
        for item in batch
        if isinstance(item.get("asset_id"), str)
    }
    recent_asset_ids = string_items(profile.get("recent_asset_ids", []))
    touched_assets = sorted(set(recent_asset_ids).intersection(latest_assets))
    resolved_assets = sorted(
        asset_id
        for asset_id, status in statuses.items()
        if status in {"useful", "shallow"}
    )
    allowed = bool(resolved_assets or touched_assets)
    return {
        "allowed": allowed,
        "reason": (
            "reveal response observed"
            if allowed
            else "waiting for response to revealed asset"
        ),
        "binding_id": binding_id,
        "attacker_key": attacker_key,
        "revealed_assets": sorted(latest_assets),
        "resolved_assets": resolved_assets,
        "recent_touched_assets": touched_assets,
        "statuses": statuses,
    }


def _response_gate_controller_response(gate_decision: dict[str, Any]) -> dict[str, Any]:
    """Build the no-reveal trace payload written when the response gate blocks.

    The trace is intentionally shaped like a controller response so dashboard
    and evaluation readers can explain why no runtime action happened.
    """
    return {
        "candidate_asset_ids": [],
        "actions": [],
        "dropped_actions": [],
        "decision_events": [
            {
                "reason": "waiting for response to revealed asset",
                "details": {
                    "reveal_action": "no_reveal",
                    "no_reveal_reason": "waiting_for_reveal_response",
                    "response_gate": gate_decision,
                },
            }
        ],
    }


def _feedback_records_for_binding(
    payload: dict[str, Any],
    attacker_key: str,
    binding_id: str,
) -> list[dict[str, Any]]:
    """Return reveal feedback rows for one attacker binding."""
    pending = payload.get("pending", [])
    if not isinstance(pending, list):
        return []
    return [
        item
        for item in pending
        if isinstance(item, dict)
        and item.get("attacker_key") == attacker_key
        and item.get("binding_id") == binding_id
    ]


def _latest_feedback_record(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick the newest feedback row, using list order to break timestamp ties."""
    indexed = list(enumerate(records))
    _, latest = max(indexed, key=lambda pair: (_feedback_ts_seconds(pair[1]), pair[0]))
    return latest


def _latest_reveal_batch(
    records: list[dict[str, Any]],
    latest: dict[str, Any],
    latest_assets: set[str],
) -> list[dict[str, Any]]:
    """Return rows from the same reveal batch as the latest row.

    One controller tick may reveal two assets, for example a main asset and an
    explore asset. `record_reveal_feedback()` writes one row per asset but gives
    each row the same `revealed_assets` set, so touching either row can release
    the whole batch.
    """
    latest_ts = parse_iso_datetime(latest.get("ts"))
    batch = [
        item
        for item in records
        if _feedback_revealed_assets(item) == latest_assets
        and _close_feedback_ts(item, latest_ts)
    ]
    return batch or [latest]


def _feedback_revealed_assets(item: dict[str, Any]) -> set[str]:
    """Return the full reveal-batch asset set recorded with one feedback row."""
    revealed_assets = set(string_items(item.get("revealed_assets", [])))
    asset_id = item.get("asset_id")
    if not revealed_assets and isinstance(asset_id, str):
        revealed_assets.add(asset_id)
    return revealed_assets


def _feedback_ts_seconds(item: dict[str, Any]) -> float:
    """Convert a feedback timestamp into a sortable UTC timestamp."""
    ts = parse_iso_datetime(item.get("ts"))
    return ts.timestamp() if ts is not None else 0.0


def _close_feedback_ts(item: dict[str, Any], latest_ts: datetime | None) -> bool:
    """Treat rows written within one tick as one reveal batch.

    Feedback rows are appended separately, so their timestamps may differ by a
    tiny amount even though they came from the same controller decision.
    """
    if latest_ts is None:
        return True
    ts = parse_iso_datetime(item.get("ts"))
    if ts is None:
        return False
    return abs((latest_ts - ts).total_seconds()) <= 5


def _no_apply_orchestrator_response(binding: dict[str, Any]) -> dict[str, Any]:
    """Build a trace placeholder when the controller intentionally reveals nothing."""
    return {
        "binding": binding,
        "route_updates": [],
        "runtime_events": [],
    }


def record_reveal_feedback(
    *,
    feedback_file: Path,
    attacker_key: str,
    binding_id: str,
    controller_response: dict[str, Any],
    applied_actions: list[dict[str, Any]],
) -> None:
    """Persist applied reveal choices for later evaluation.

    Example:
        action asset_id="git-internal" plus details selected_technique="T1213"
        records one pending reveal in `data/runtime/reveal_feedback.json`.
    """
    # only unlock actions trigger feedback, and one action may reveal multiple assets via target_asset_id, so gather all the revealed asset_ids for feedback records
    feedback_actions = [
        action
        for action in applied_actions
        if action.get("action_type") == "unlock"
    ]
    applied_asset_ids = {
        asset_id
        for action in feedback_actions
        for asset_id in (action.get("asset_id"), action.get("target_asset_id"))
        if isinstance(asset_id, str)
    }
    if not applied_asset_ids:
        return
    repository = FileRevealFeedbackRepository(feedback_file)
    available_assets = string_items(controller_response.get("candidate_asset_ids", []))
    revealed_assets = dedupe_preserve(
        [
            asset_id
            for action in feedback_actions
            for asset_id in (action.get("asset_id"), action.get("target_asset_id"))
            if isinstance(asset_id, str)
        ]
    )
    for decision in controller_response.get("decision_events", []):
        if not isinstance(decision, dict):
            continue
        asset_id = decision.get("asset_added")
        if asset_id not in applied_asset_ids:
            continue
        details = decision.get("details", {})
        if not isinstance(details, dict):
            continue
        asset_group = details.get("asset_group")
        if not isinstance(asset_group, str):
            continue
        context_key = _reveal_context_key(
            details.get("selected_technique"),
            string_items(details.get("matched_dependency_markers", [])),
        )
        repository.record_reveal(
            context_key=context_key,
            asset_group=asset_group,
            binding_id=binding_id,
            attacker_key=attacker_key,
            asset_id=str(asset_id),
            available_assets=available_assets,
            revealed_assets=revealed_assets,
        )


def update_reveal_feedback_from_evidence(
    *,
    feedback_file: Path,
    evidence_file: Path,
    internal_http_events_file: Path | None = None,
    feedback_window_seconds: int,
) -> None:
    """Resolve pending reveal feedback from later profiler evidence.

    Example:
        pending finance-share + later evidence source_ref.asset_id=finance-share
        with tech_id="T1005" marks the reveal `useful`.
    """
    payload = read_json_object(feedback_file, {"schema_version": "v1", "contexts": {}, "pending": []})
    pending = payload.get("pending", [])
    if not isinstance(pending, list) or not pending:
        return
    evidence_records = evidence_records_from_file(evidence_file)
    internal_http_events = (
        _internal_http_event_records(internal_http_events_file)
        if internal_http_events_file is not None
        else []
    )
    now = datetime.now(timezone.utc)
    changed = False

    for item in pending:
        if not isinstance(item, dict) or item.get("status") != "pending":
            continue
        touch_outcome = _pending_reveal_outcome(item, evidence_records)
        if touch_outcome is None:
            touch_outcome = _pending_internal_http_touch_outcome(
                item,
                internal_http_events,
            )
        expired = _pending_reveal_expired(item, now, feedback_window_seconds)
        if touch_outcome is None and not expired:
            continue
        outcome = touch_outcome or "ignored"
        context_key = item.get("context_key")
        asset_group = item.get("asset_group")
        if isinstance(context_key, str) and isinstance(asset_group, str):
            group = mutable_nested_dict(payload, ("contexts", context_key, "asset_groups", asset_group))
            group[outcome] = int(group.get(outcome, 0) or 0) + 1
        item["status"] = outcome
        item["resolved_at"] = now.isoformat().replace("+00:00", "Z")
        changed = True

    if changed:
        with feedback_file.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")


def _reveal_context_key(technique: object, markers: list[str]) -> str:
    """Build a stable feedback context from controller decision details."""
    selected = technique if isinstance(technique, str) and technique else "unknown"
    return "|".join([selected, *sorted(markers)])


def _pending_reveal_outcome(
    pending: dict[str, Any],
    evidence_records: list[dict[str, Any]],
) -> str | None:
    """Return useful/shallow if later evidence explicitly references the asset."""
    asset_id = pending.get("asset_id")
    attacker_key = pending.get("attacker_key")
    pending_ts = parse_iso_datetime(pending.get("ts"))
    if not isinstance(asset_id, str) or not isinstance(attacker_key, str):
        return None
    for evidence in evidence_records:
        if evidence.get("attacker_key") != attacker_key:
            continue
        evidence_ts = parse_iso_datetime(evidence.get("ts"))
        if pending_ts is not None and evidence_ts is not None and evidence_ts < pending_ts:
            continue
        source_ref = evidence.get("source_ref", {})
        if isinstance(source_ref, dict) and source_ref.get("asset_id") == asset_id:
            return "useful" if evidence.get("tech_id") or evidence.get("group") else "shallow"
    return None


def _pending_internal_http_touch_outcome(
    pending: dict[str, Any],
    events: list[dict[str, Any]],
) -> str | None:
    """Return shallow when raw asset-gateway HTTP logs show an unmapped touch."""
    asset_id = pending.get("asset_id")
    attacker_key = pending.get("attacker_key")
    pending_ts = parse_iso_datetime(pending.get("ts"))
    if not isinstance(asset_id, str) or not isinstance(attacker_key, str):
        return None
    for event in events:
        if event.get("attacker_key") != attacker_key:
            continue
        if event.get("asset_id") != asset_id:
            continue
        event_ts = parse_iso_datetime(event.get("ts"))
        if pending_ts is not None and event_ts is not None and event_ts < pending_ts:
            continue
        return "shallow"
    return None


def _internal_http_event_records(path: Path) -> list[dict[str, Any]]:
    """Read raw asset-gateway internal HTTP JSONL events for shallow touches."""
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _pending_reveal_expired(
    pending: dict[str, Any],
    now: datetime,
    feedback_window_seconds: int,
) -> bool:
    ts = parse_iso_datetime(pending.get("ts"))
    if ts is None:
        return False
    return (now - ts).total_seconds() > feedback_window_seconds


def _processed_evidence_map(state: dict[str, Any]) -> dict[str, list[str]]:
    """Return the mutable attacker -> processed evidence ids map."""
    processed = state.setdefault("processed_evidence_ids_by_attacker", {})
    if not isinstance(processed, dict):
        processed = {}
        state["processed_evidence_ids_by_attacker"] = processed
    return processed


def _has_new_evidence(
    state: dict[str, Any],
    attacker_key: str,
    recent_evidence_ids: list[str],
) -> bool:
    """Return True only when this profile contains unprocessed evidence ids."""
    if not recent_evidence_ids:
        return False
    processed = _processed_evidence_map(state).get(attacker_key, [])
    processed_ids = set(processed if isinstance(processed, list) else [])
    return any(evidence_id not in processed_ids for evidence_id in recent_evidence_ids)


def _mark_evidence_processed(
    state: dict[str, Any],
    attacker_key: str,
    recent_evidence_ids: list[str],
) -> None:
    """Remember the profile evidence ids that have already triggered a tick."""
    processed = _processed_evidence_map(state)
    previous = processed.get(attacker_key, [])
    previous_ids = [item for item in previous if isinstance(item, str)]
    processed[attacker_key] = dedupe_preserve([*previous_ids, *recent_evidence_ids])


def _limit_reveal_actions(
    actions: list[Any],
    max_actions_per_trigger: int,
) -> list[Any]:
    """Keep at most N unlock/configure actions while preserving other actions."""
    if max_actions_per_trigger <= 0:
        return []

    limited: list[Any] = []
    reveal_count = 0
    for action in actions:
        if not isinstance(action, dict) or not _is_reveal_action(action):
            limited.append(action)
            continue
        if reveal_count >= max_actions_per_trigger:
            continue
        limited.append(action)
        reveal_count += 1
    return limited


def _reveal_actions(actions: list[Any]) -> list[dict[str, Any]]:
    """Return controller actions that actually reveal an asset or config."""
    return [
        action
        for action in actions
        if isinstance(action, dict) and _is_reveal_action(action)
    ]


def _is_reveal_action(action: dict[str, Any]) -> bool:
    return action.get("action_type") in {"unlock", "configure"}


def _dropped_actions(
    original_actions: list[Any],
    applied_actions: list[Any],
) -> list[Any]:
    """Return controller actions dropped by the demo rate limiter."""
    applied_ids = {id(action) for action in applied_actions}
    return [action for action in original_actions if id(action) not in applied_ids]


def build_trace_record(
    attacker_key: str,
    binding: dict[str, Any],
    profile: dict[str, Any],
    controller_response: dict[str, Any],
    orchestrator_response: dict[str, Any],
) -> dict[str, Any]:
    """Build one explainability record for a controller/orchestrator cycle.

    The trace intentionally keeps only the fields useful for a demo write-up:
    what the profile looked like, what the controller considered, what action it
    chose, and which runtime ports were opened after the orchestrator applied it.
    """
    binding_after = orchestrator_response.get("binding", {})
    binding_after = binding_after if isinstance(binding_after, dict) else {}
    return {
        "schema_version": "v1",
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "attacker_key": attacker_key,
        "binding_id": binding.get("binding_id"),
        "recent_tactics": profile.get("recent_tactics", []),
        "recent_techniques": profile.get("recent_techniques", []),
        "recent_evidence_ids": profile.get("recent_evidence_ids", []),
        "unlocked_assets_before": binding.get("unlocked_assets", []),
        "revealed_configurations_before": binding.get("revealed_configurations", {}),
        "candidate_asset_ids": controller_response.get("candidate_asset_ids", []),
        "actions": controller_response.get("actions", []),
        "dropped_actions": controller_response.get("dropped_actions", []),
        "decision_events": controller_response.get("decision_events", []),
        "route_updates": orchestrator_response.get("route_updates", []),
        "runtime_events": _summarize_runtime_events(
            orchestrator_response.get("runtime_events", [])
        ),
        "unlocked_assets_after": binding_after.get("unlocked_assets", []),
        "revealed_configurations_after": binding_after.get("revealed_configurations", {}),
    }


def append_trace_record(path: Path, record: dict[str, Any]) -> None:
    """Append one decision trace record to a runtime JSON file.

    File shape:
        {"records": [{...one adaptive decision trace...}]}
    """
    payload = read_json_object(path, {"records": []})
    records = payload.get("records", [])
    if not isinstance(records, list):
        records = []
    records.append(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump({"records": records}, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _summarize_runtime_events(raw_events: object) -> list[dict[str, Any]]:
    """Keep runtime trace records compact and centered on opened ports."""
    if not isinstance(raw_events, list):
        return []
    summaries: list[dict[str, Any]] = []
    for event in raw_events:
        if not isinstance(event, dict):
            continue
        settings = event.get("settings", {})
        settings = settings if isinstance(settings, dict) else {}
        summaries.append(
            {
                "asset_id": event.get("asset_id"),
                "asset_name": event.get("asset_name"),
                "status": event.get("status"),
                "template_family": event.get("template_family"),
                "runtime_backend": settings.get("runtime_backend", "mock"),
                "image": settings.get("image"),
                "port_mappings": settings.get("port_mappings", []),
            }
        )
    return summaries


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
        "--trace-file",
        type=Path,
        default=Path("data/runtime/decision_trace.json"),
        help="Decision trace JSON file written when unlock actions are applied.",
    )
    parser.add_argument(
        "--loop-state-file",
        type=Path,
        default=Path("data/runtime/adaptive_loop_state.json"),
        help="Progress file used to avoid reprocessing the same evidence ids.",
    )
    parser.add_argument(
        "--feedback-file",
        type=Path,
        default=Path("data/runtime/reveal_feedback.json"),
        help="Reveal feedback JSON file used for evaluation traces.",
    )
    parser.add_argument(
        "--feedback-window-seconds",
        type=int,
        default=int(os.getenv("HONEYPOT_FEEDBACK_WINDOW_SECONDS", "300")),
        help="Seconds before a pending reveal is counted as ignored.",
    )
    parser.add_argument(
        "--max-actions-per-trigger",
        type=int,
        default=2,
        help="Maximum unlock/configure actions to apply for one new evidence trigger.",
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
                trace_file=args.trace_file,
                loop_state_file=args.loop_state_file,
                feedback_file=args.feedback_file,
                feedback_window_seconds=args.feedback_window_seconds,
                max_actions_per_trigger=args.max_actions_per_trigger,
            )
        except (HTTPError, URLError, TimeoutError, RuntimeError, json.JSONDecodeError) as exc:
            print(f"[adaptive] tick failed: {exc}", file=sys.stderr, flush=True)

        if args.once:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
