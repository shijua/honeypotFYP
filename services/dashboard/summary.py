"""Build dashboard summaries from runtime JSON state."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
from typing import Any

from libs.common.clock import parse_iso_datetime
from libs.common.config import RuntimeConfig
from libs.common.iterables import dedupe_preserve
from libs.common.json_utils import read_json_object
from libs.common.runtime_records import evidence_records as evidence_records_from_file
from libs.common.runtime_records import list_records


@dataclass(frozen=True)
class DockerStatusProbe:
    """Result of asking Docker which honeynet containers currently exist."""

    statuses: dict[str, str]
    error: str | None = None


def summarize_demo(state_dir: Path) -> dict[str, Any]:
    """Build a deterministic dashboard report from runtime JSON files."""
    cowrie_observations = list_records(
        state_dir / "cowrie_observations.json",
        "observations",
    )
    entrypoint_observations = list_records(
        state_dir / "entrypoint_observations.json",
        "observations",
    )
    opencanary_observations = list_records(
        state_dir / "opencanary_observations.json",
        "observations",
    )
    high_interaction_observations = list_records(
        state_dir / "high_interaction_observations.json",
        "observations",
    )
    observations = [
        *entrypoint_observations,
        *cowrie_observations,
        *opencanary_observations,
        *high_interaction_observations,
    ]
    bindings = list_records(state_dir / "bindings.json", "records")
    runtime_records = list_records(state_dir / "asset_runtime.json", "records")
    decision_trace = list_records(state_dir / "decision_trace.json", "records")
    evidence_records = evidence_records_from_file(
        state_dir / "evidence.json",
        include_bucket_attacker=True,
    )
    profiles_payload = read_json_object(state_dir / "profiles.json", {"profiles": {}})
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
    config = RuntimeConfig()

    historical_assets = [
        _runtime_summary(item, docker_probe)
        for item in attacker_runtime
    ]
    current_assets = _current_runtime_assets(historical_assets)
    failed_assets = _failed_runtime_assets(historical_assets, current_assets)
    unlocked_assets = binding.get("unlocked_assets", []) if binding else []
    unlocked_assets = _ordered_unlocked_assets(unlocked_assets, historical_assets)

    return {
        "attacker_key": attacker_key,
        "binding_id": binding_id,
        "event_counts": dict(
            sorted(Counter(_eventids(attacker_observations)).items())
        ),
        "commands": _commands(attacker_observations),
        "public_http_evidence": _recent_http_evidence(
            attacker_evidence,
            "public_http",
            profile,
            config.chain_window_seconds,
        ),
        "internal_http_evidence": _recent_http_evidence(
            attacker_evidence,
            "internal_http",
            profile,
            config.chain_window_seconds,
        ),
        "recent_tactics": _ordered_profile_values(
            profile.get("recent_tactics", []),
            attacker_evidence,
            "group",
        ),
        "recent_techniques": _ordered_profile_values(
            profile.get("recent_techniques", []),
            attacker_evidence,
            "tech_id",
        ),
        "confidence_by_technique": profile.get("conf_by_technique", {}),
        # These fields explain why catalog-gated internal assets became
        # eligible, e.g. a .bak request on the public site unlocking finance.
        "recent_public_http_paths": profile.get("recent_public_http_paths", []),
        "recent_public_http_rules": profile.get("recent_public_http_rules", []),
        "recent_public_http_indicators": profile.get("recent_public_http_indicators", []),
        "recent_internal_http_paths": profile.get("recent_internal_http_paths", []),
        "recent_internal_http_rules": profile.get("recent_internal_http_rules", []),
        "recent_internal_http_indicators": profile.get("recent_internal_http_indicators", []),
        "confidence_by_tactic": profile.get("conf_by_tactic", {}),
        "docker_probe_error": docker_probe.error,
        "unlocked_assets": unlocked_assets,
        "historical_opened_assets": historical_assets,
        "current_running_assets": current_assets,
        "failed_assets": failed_assets,
        "decisions": [
            _decision_summary(item, attacker_evidence)
            for item in attacker_trace
        ],
    }


def _latest_binding(
    attacker_key: str,
    bindings: list[dict[str, Any]],
) -> dict[str, Any] | None:
    matches = [item for item in bindings if item.get("attacker_key") == attacker_key]
    if not matches:
        return None
    return sorted(matches, key=lambda item: str(item.get("last_seen_ts", "")))[-1]


def _ordered_unlocked_assets(
    unlocked_assets: object,
    historical_assets: list[dict[str, Any]],
) -> list[str]:
    """Return unlocked assets in reveal order when runtime timestamps exist."""
    raw_unlocked = unlocked_assets if isinstance(unlocked_assets, list) else []
    unlocked = [str(asset_id) for asset_id in raw_unlocked if asset_id]
    if not unlocked:
        return []
    opened_ids = [
        str(asset.get("asset_id"))
        for asset in sorted(historical_assets, key=lambda item: str(item.get("started_at", "")))
        if asset.get("asset_id")
    ]
    ordered = dedupe_preserve([asset_id for asset_id in opened_ids if asset_id in unlocked])
    return dedupe_preserve([*ordered, *unlocked])


def _ordered_profile_values(
    profile_values: object,
    evidence_records: list[dict[str, Any]],
    evidence_field: str,
) -> list[str]:
    """Order profile tactics/techniques by when supporting evidence appeared."""
    values = [str(value) for value in profile_values if value] if isinstance(profile_values, list) else []
    if not values:
        return []
    value_set = set(values)
    evidence_values = [
        str(item.get(evidence_field))
        for item in sorted(evidence_records, key=lambda record: str(record.get("ts", "")))
        if item.get(evidence_field) in value_set
    ]
    return dedupe_preserve([*evidence_values, *values])


def _eventids(observations: list[dict[str, Any]]) -> list[str]:
    eventids: list[str] = []
    for item in observations:
        if isinstance(item.get("eventid"), str):
            eventids.append(str(item["eventid"]))
            continue
        if isinstance(item.get("service"), str):
            source = item.get("source")
            if isinstance(source, str) and source:
                eventids.append(f"{source}.{item['service']}")
            continue
        if isinstance(item.get("method"), str) and isinstance(item.get("path"), str):
            surface = item.get("surface")
            if isinstance(surface, str) and surface:
                eventids.append(f"{surface}_http.{str(item['method']).upper()}")
    return eventids


def _commands(observations: list[dict[str, Any]]) -> list[str]:
    commands = [
        str(item["command"]).strip()
        for item in observations
        if item.get("eventid") == "cowrie.command.input"
        and isinstance(item.get("command"), str)
        and str(item.get("command")).strip()
    ]
    return dedupe_preserve(commands)


def _http_evidence(evidences: list[dict[str, Any]], source: str) -> list[str]:
    """Return concise HTTP evidence for the attacker card."""
    evidence: list[str] = []
    for item in evidences:
        source_ref = item.get("source_ref")
        if not isinstance(source_ref, dict):
            continue
        if source_ref.get("source") != source:
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
    return dedupe_preserve(evidence)


def _recent_http_evidence(
    evidences: list[dict[str, Any]],
    source: str,
    profile: dict[str, Any],
    window_seconds: int,
) -> list[str]:
    """Return time-sorted HTTP evidence inside the profile's recent window."""
    source_evidences = [
        item
        for item in evidences
        if isinstance(item.get("source_ref"), dict)
        and item["source_ref"].get("source") == source
    ]
    if not source_evidences:
        return []

    updated_at = parse_iso_datetime(profile.get("updated_at"))
    if updated_at is None:
        updated_at = max(
            (parse_iso_datetime(item.get("ts")) for item in source_evidences),
            default=None,
        )
    if updated_at is None:
        return _http_evidence(source_evidences, source)

    cutoff = updated_at - timedelta(seconds=window_seconds)
    recent = [
        item
        for item in source_evidences
        if (ts := parse_iso_datetime(item.get("ts"))) is not None and ts >= cutoff
    ]
    minimum_ts = datetime.min.replace(tzinfo=timezone.utc)
    recent.sort(key=lambda item: parse_iso_datetime(item.get("ts")) or minimum_ts)
    return _http_evidence(recent, source)


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
    active_configuration_ids = _active_configuration_ids(settings)
    return {
        "asset_id": record.get("asset_id"),
        "asset_name": record.get("asset_name"),
        "started_at": record.get("started_at"),
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
        "configured_runtime": bool(settings.get("configured_runtime")),
        "active_configuration_ids": active_configuration_ids,
        "ports": [_format_port_mapping(item) for item in _port_mappings(settings)],
    }


def _active_configuration_ids(settings: dict[str, Any]) -> list[str]:
    active_configurations = settings.get("active_configurations", {})
    if not isinstance(active_configurations, dict):
        return []
    return sorted(str(configuration_id) for configuration_id in active_configurations)


def _asset_summary_is_failed(asset: dict[str, Any]) -> bool:
    if asset.get("status") == "failed":
        return True
    if asset.get("status") == "stopped":
        return False
    if asset.get("runtime_backend") not in {"docker", "compose"}:
        return False
    current_status = str(asset.get("current_container_status", ""))
    container_statuses = asset.get("container_statuses", {})
    if asset.get("runtime_backend") == "compose" and isinstance(container_statuses, dict):
        statuses = [str(status) for status in container_statuses.values()]
        return not statuses or any(not status.startswith("Up") for status in statuses)
    return bool(current_status) and current_status not in {"unknown", "unavailable"} and not current_status.startswith("Up")


def _asset_summary_key(asset: dict[str, Any]) -> str:
    return str(asset.get("asset_id") or asset.get("container_name") or "")


def _current_runtime_assets(historical_assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest_running_by_asset: dict[str, dict[str, Any]] = {}
    for asset in historical_assets:
        if asset.get("runtime_backend") not in {"docker", "compose"}:
            continue
        if not str(asset.get("current_container_status", "")).startswith("Up"):
            continue
        if _asset_summary_is_failed(asset):
            continue
        latest_running_by_asset[_asset_summary_key(asset)] = asset
    return list(latest_running_by_asset.values())


def _failed_runtime_assets(
    historical_assets: list[dict[str, Any]],
    current_assets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    running_keys = {_asset_summary_key(asset) for asset in current_assets}
    return [
        asset
        for asset in historical_assets
        if _asset_summary_key(asset) not in running_keys and _asset_summary_is_failed(asset)
    ]


def _decision_summary(
    record: dict[str, Any],
    evidence_records: list[dict[str, Any]],
) -> dict[str, Any]:
    actions = record.get("actions", [])
    actions = actions if isinstance(actions, list) else []
    dropped_actions = record.get("dropped_actions", [])
    dropped_actions = dropped_actions if isinstance(dropped_actions, list) else []
    decision_events = record.get("decision_events", [])
    decision_events = decision_events if isinstance(decision_events, list) else []
    recent_evidence_ids = [
        str(evidence_id)
        for evidence_id in record.get("recent_evidence_ids", [])
        if evidence_id
    ]
    return {
        "ts": record.get("ts"),
        "recent_tactics": record.get("recent_tactics", []),
        "recent_techniques": record.get("recent_techniques", []),
        "recent_evidence_ids": recent_evidence_ids,
        "trigger_evidence": _trigger_evidence_summaries(
            recent_evidence_ids,
            evidence_records,
        ),
        "candidate_asset_ids": record.get("candidate_asset_ids", []),
        "actions": [
            _action_summary(action)
            for action in actions
            if isinstance(action, dict)
        ],
        "action_asset_ids": [
            action.get("asset_id")
            for action in actions
            if isinstance(action, dict) and action.get("action_type") == "unlock"
        ],
        "dropped_actions": [
            _action_summary(action)
            for action in dropped_actions
            if isinstance(action, dict)
        ],
        "dropped_action_asset_ids": [
            action.get("asset_id")
            for action in dropped_actions
            if isinstance(action, dict) and action.get("action_type") == "unlock"
        ],
        "decision_events": [
            _decision_event_summary(event)
            for event in decision_events
            if isinstance(event, dict)
        ],
        "reasons": [
            event.get("reason")
            for event in decision_events
            if isinstance(event, dict) and event.get("reason")
        ],
        "route_updates": record.get("route_updates", []),
        "runtime_events": record.get("runtime_events", []),
    }


def _trigger_evidence_summaries(
    evidence_ids: list[str],
    evidence_records: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Summarize evidence that produced a controller tick."""
    by_id = {
        str(item.get("evidence_id")): item
        for item in evidence_records
        if item.get("evidence_id")
    }
    summaries = [
        summary
        for evidence_id in evidence_ids
        if (summary := _trigger_evidence_summary(by_id.get(evidence_id)))
    ]
    seen: set[str] = set()
    deduped: list[dict[str, str]] = []
    for summary in summaries:
        key = summary.get("text", "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(summary)
    return deduped


def _trigger_evidence_summary(item: dict[str, Any] | None) -> dict[str, str] | None:
    if not isinstance(item, dict):
        return None
    source_ref = item.get("source_ref")
    source_ref = source_ref if isinstance(source_ref, dict) else {}
    source = str(source_ref.get("source") or item.get("source") or "evidence")
    label = str(item.get("reason") or source)
    detail = ""
    if source in {"public_http", "internal_http"}:
        method = str(source_ref.get("http_method") or "HTTP").upper()
        path = source_ref.get("http_path")
        query = source_ref.get("http_query_string")
        detail = str(path or "")
        if detail and isinstance(query, str) and query:
            detail = f"{detail}?{query}"
        if detail:
            detail = f"{method} {detail}"
    elif source == "cowrie":
        detail = _cowrie_command_from_source_ref(source_ref)
    elif source == "opencanary":
        detail = str(source_ref.get("service") or "")
    if not detail:
        detail = str(item.get("tech_id") or item.get("group") or "")
    text = f"cmd:{detail}" if source == "cowrie" and detail else f"{source}:{detail}" if detail else source
    return {
        "evidence_id": str(item.get("evidence_id")),
        "source": source,
        "label": label,
        "detail": detail,
        "text": text,
    }


def _cowrie_command_from_source_ref(source_ref: dict[str, Any]) -> str:
    """Extract the original Cowrie command from structured fields or output text."""
    command = source_ref.get("command") or source_ref.get("input")
    if isinstance(command, str) and command.strip():
        return command.strip()
    output = source_ref.get("output")
    if not isinstance(output, str):
        return ""
    # Example: "cowrie.command.input from 146.169.44.23: cat /etc/passwd [rule]"
    _, separator, tail = output.partition(": ")
    if not separator:
        return ""
    command_text = tail.split(" [", 1)[0].strip()
    return command_text


def _action_summary(action: dict[str, Any]) -> dict[str, Any]:
    return {
        "action_type": action.get("action_type"),
        "asset_id": action.get("asset_id"),
        "configuration_id": action.get("configuration_id"),
        "target_asset_id": action.get("target_asset_id"),
    }


def _decision_event_summary(event: dict[str, Any]) -> dict[str, Any]:
    """Keep only controller fields that explain why a reveal happened."""
    details = event.get("details", {})
    details = details if isinstance(details, dict) else {}
    configuration = details.get("configuration_reveal", {})
    configuration = configuration if isinstance(configuration, dict) else {}
    eligible_reveal_options = details.get("eligible_reveal_options", [])
    eligible_reveal_options = (
        eligible_reveal_options if isinstance(eligible_reveal_options, list) else []
    )
    if not eligible_reveal_options:
        eligible_assets = details.get("eligible_assets", [])
        eligible_assets = eligible_assets if isinstance(eligible_assets, list) else []
        eligible_reveal_options = [
            {"action_type": "unlock", "asset_id": asset_id}
            for asset_id in eligible_assets
        ]
    normalized_reveal_options = [
        _reveal_option_summary(option)
        for option in eligible_reveal_options
        if isinstance(option, dict)
    ]
    rejected_assets = details.get("rejected_assets", {})
    rejected_assets = rejected_assets if isinstance(rejected_assets, dict) else {}
    matched_markers = details.get("matched_dependency_markers", [])
    matched_markers = matched_markers if isinstance(matched_markers, list) else []
    observed_techniques = details.get("observed_techniques", [])
    observed_techniques = observed_techniques if isinstance(observed_techniques, list) else []
    covered_techniques = details.get("covered_techniques", [])
    covered_techniques = covered_techniques if isinstance(covered_techniques, list) else []
    return {
        "ts": event.get("ts"),
        "decision_type": event.get("decision_type"),
        "asset_id": event.get("asset_added"),
        "reason": event.get("reason"),
        "reveal_role": details.get("reveal_role"),
        "strategy": details.get("selected_strategy") or details.get("strategy"),
        "candidate_type": details.get("candidate_type"),
        "selected_technique": details.get("selected_technique"),
        "confidence_score": details.get("confidence_score"),
        "recommendation_support": details.get("recommendation_support"),
        "expected_technique_gain": details.get("expected_technique_gain"),
        "covered_techniques": covered_techniques,
        "asset_group": details.get("asset_group"),
        "configuration_id": configuration.get("configuration_id"),
        "target_asset_id": configuration.get("target_asset_id"),
        "eligible_reveal_options": normalized_reveal_options,
        "eligible_reveal_option_count": len(normalized_reveal_options),
        "rejected_asset_count": len(rejected_assets),
        "rejection_reason_counts": _value_counts(rejected_assets.values()),
        "matched_dependency_markers": matched_markers,
        "observed_techniques": observed_techniques,
        "prior_support_enabled": details.get("prior_support_enabled"),
        "prior_degraded": details.get("prior_degraded"),
        "no_reveal_reason": details.get("no_reveal_reason"),
    }


def _reveal_option_summary(option: dict[str, Any]) -> dict[str, Any]:
    """Return the stable identity of one unlock or configuration option."""
    return {
        "action_type": option.get("action_type"),
        "asset_id": option.get("asset_id"),
        "configuration_id": option.get("configuration_id"),
        "target_asset_id": option.get("target_asset_id"),
    }


def _value_counts(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        label = str(value)
        counts[label] = counts.get(label, 0) + 1
    return counts


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
