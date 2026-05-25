"""Sigma-backed matcher for normalized high-interaction honeypot events.

The high-interaction forwarder turns Dionaea and Honeytrap logs into
one `HighInteractionLogEvent` shape. This module then applies a small Sigma
subset to that normalized shape and returns profiler-ready ATT&CK tags.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from libs.common.iterables import dedupe_preserve
from libs.common.sigma import (
    SigmaSelectionPlan,
    sigma_attack_profile_tags,
    sigma_files,
    sigma_keyword_to_regex,
    sigma_selection_plans,
    sigma_values,
    split_sigma_field,
)
from libs.contracts.models import HighInteractionLogEvent


DEFAULT_HIGH_INTERACTION_SIGMA_RULES_PATH = Path("data/detections/high_interaction_sigma")

# The YAML rules use readable Sigma-style field names, while the runtime event
# is a project model. This map is the schema bridge. Example:
#   YAML field `destination.port` -> normalized event field `dst_port`.
FIELD_ALIASES = {
    "honeynet.source": "source",
    "honeynet_source": "source",
    "source": "source",
    "event_source": "source",
    "honeynet.service": "service",
    "honeynet_service": "service",
    "service": "service",
    "protocol": "service",
    "event_type": "event_type",
    "event.action": "event_type",
    "event_action": "event_type",
    "eventid": "event_type",
    "honeynet.asset_id": "asset_id",
    "honeynet_asset_id": "asset_id",
    "asset_id": "asset_id",
    "source.ip": "src_host",
    "source_ip": "src_host",
    "src_ip": "src_host",
    "src_host": "src_host",
    "destination.ip": "dst_host",
    "destination_ip": "dst_host",
    "dst_ip": "dst_host",
    "dst_host": "dst_host",
    "destination.port": "dst_port",
    "destination_port": "dst_port",
    "dst_port": "dst_port",
    "logdata.message": "logdata_message",
    "logdata_message": "logdata_message",
    "message": "logdata_message",
    "logdata": "logdata",
    "request": "logdata",
    "payload": "logdata",
    "combined": "combined",
}


@dataclass(frozen=True)
class HighInteractionRuleMatch:
    """One matched high-interaction Sigma rule.

    Example:
        rule_name="dionaea_payload_transfer",
        tags=("mitre_initial_access", "T1190"),
        indicators=("logdata:payload", "logdata:download").
    """

    rule_name: str
    tags: tuple[str, ...]
    indicators: tuple[str, ...]


@dataclass(frozen=True)
class SigmaHighInteractionRule:
    """One high-interaction Sigma rule prepared for runtime matching.

    `plans` are parsed Sigma condition branches from `libs.common.sigma`. Each
    plan has positive selections that must match and negative selections that
    veto the match.
    """

    name: str
    tags: tuple[str, ...]
    plans: tuple[SigmaSelectionPlan, ...]


class FileHighInteractionSigmaRuleMatcher:
    """Load high-interaction Sigma YAML and match normalized backend events.

    Example:
        matcher = FileHighInteractionSigmaRuleMatcher()
        matcher.tags_for(dionaea_download_event) -> ["mitre_initial_access", "T1190", ...]
    """

    def __init__(self, path: str | Path = DEFAULT_HIGH_INTERACTION_SIGMA_RULES_PATH) -> None:
        self._path = Path(path)
        self._rules: tuple[SigmaHighInteractionRule, ...] | None = None

    def tags_for(self, event: HighInteractionLogEvent) -> list[str]:
        """Return profiler tags from matching Sigma ATT&CK tags.

        Example:
            Dionaea event_type=download.offer with logdata payload -> T1190, T1204.002, T1105.
        """
        tags: list[str] = []
        for match in self.matches_for(event):
            tags.extend(match.tags)
        return dedupe_preserve(tags)

    def matches_for(self, event: HighInteractionLogEvent) -> list[HighInteractionRuleMatch]:
        """Return full rule matches for debugging and decision traces.

        Example:
            Dionaea download event -> match name + ATT&CK tags + indicators that
            explain which normalized fields caused the match.
        """
        fields = _normalize_event_fields(event)
        matches: list[HighInteractionRuleMatch] = []
        for rule in self._load_rules():
            indicators = _rule_indicators(rule, fields)
            if not indicators:
                continue
            matches.append(
                HighInteractionRuleMatch(
                    rule_name=rule.name,
                    tags=rule.tags,
                    indicators=tuple(dedupe_preserve(indicators)),
                )
            )
        return matches

    def _load_rules(self) -> tuple[SigmaHighInteractionRule, ...]:
        if self._rules is not None:
            return self._rules
        self._rules = tuple(
            rule
            for path in sigma_files(self._path, label="High-interaction Sigma rule path")
            if (rule := _rule_from_sigma_file(path)) is not None
        )
        return self._rules


def _rule_from_sigma_file(path: Path) -> SigmaHighInteractionRule | None:
    """Parse one YAML file into a runtime rule or skip unsupported files.

    Input example:
        data/detections/high_interaction_sigma/dionaea_payload_transfer.yml

    Output example:
        SigmaHighInteractionRule(name="dionaea_payload_transfer", tags=("T1190", ...), plans=(...))
    """
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return None
    detection = payload.get("detection")
    if not isinstance(detection, dict):
        return None
    tags = sigma_attack_profile_tags(payload.get("tags"))
    if not tags:
        return None
    plans = tuple(sigma_selection_plans(detection))
    if not plans:
        return None
    return SigmaHighInteractionRule(
        name=_rule_name(payload, path),
        tags=tuple(tags),
        plans=plans,
    )


def _rule_indicators(
    rule: SigmaHighInteractionRule,
    fields: dict[str, str],
) -> list[str]:
    """Return indicators when any parsed Sigma condition plan matches.

    Example:
        source=dionaea + service=http + logdata contains payload/download
        -> ["source:dionaea", "service:http", "logdata:payload", "logdata:download"].
    """
    matched_indicators: list[str] = []
    for plan in rule.plans:
        indicators: list[str] = []
        for selection in plan.positives:
            selection_indicators = _selection_indicators(selection, fields)
            if not selection_indicators:
                indicators = []
                break
            indicators.extend(selection_indicators)
        if not indicators:
            continue
        if any(_selection_indicators(selection, fields) for selection in plan.negatives):
            continue
        matched_indicators.extend(indicators)
    return dedupe_preserve(matched_indicators)


def _selection_indicators(selection: object, fields: dict[str, str]) -> list[str]:
    """Match one Sigma selection against normalized event fields.

    A dict selection requires every field in the selection to match. A list
    selection is treated as keyword search over the combined event text.
    Unsupported fields return no match instead of guessing.
    """
    if isinstance(selection, list):
        return _keyword_indicators(selection, fields)
    if not isinstance(selection, dict):
        return []
    indicators: list[str] = []
    for raw_field, raw_value in selection.items():
        field, modifiers = split_sigma_field(str(raw_field))
        normalized_field = FIELD_ALIASES.get(field)
        if normalized_field is None:
            return []
        values = sigma_values(raw_value)
        if not values:
            return []
        matched = _field_indicators(normalized_field, fields[normalized_field], modifiers, values)
        if not matched:
            return []
        indicators.extend(matched)
    return indicators


def _field_indicators(
    field: str,
    observed: str,
    modifiers: set[str],
    values: list[str],
) -> list[str]:
    """Apply the Sigma string modifiers supported by this runtime matcher.

    Supported examples:
        service: http
        logdata|contains: payload
        event_type|startswith: download
        combined|re: "payload|shellcode"
    """
    if "contains" in modifiers and "all" in modifiers:
        return (
            [_format_indicator(field, value) for value in values if value in observed]
            if all(value in observed for value in values)
            else []
        )
    if "contains" in modifiers:
        return [_format_indicator(field, value) for value in values if value in observed]
    if "startswith" in modifiers:
        return [_format_indicator(field, value) for value in values if observed.startswith(value)]
    if "endswith" in modifiers:
        return [_format_indicator(field, value) for value in values if observed.endswith(value)]
    if "re" in modifiers or "regex" in modifiers:
        return [_format_indicator(field, value) for value in values if re.search(value, observed)]
    if not modifiers:
        return [_format_indicator(field, value) for value in values if observed == value]
    return []


def _keyword_indicators(selection: list[object], fields: dict[str, str]) -> list[str]:
    """Apply Sigma keyword selections to the combined normalized event text."""
    combined = fields["combined"]
    indicators: list[str] = []
    for value in selection:
        if not isinstance(value, str) or not value:
            continue
        if re.search(sigma_keyword_to_regex(value), combined):
            indicators.append(_format_indicator("combined", value))
    return indicators


def _normalize_event_fields(event: HighInteractionLogEvent) -> dict[str, str]:
    """Flatten one high-interaction event into lowercase strings for Sigma.

    Input example:
        source="dionaea", service="http", logdata={"message": "payload download"}

    Output example:
        {"source": "dionaea", "service": "http", "logdata": "payload download", ...}
    """
    logdata = _logdata_text(event.logdata)
    fields = {
        "source": event.source,
        "service": event.service,
        "event_type": event.event_type,
        "asset_id": event.asset_id,
        "src_host": event.src_host or event.attacker_key,
        "dst_host": event.dst_host or "",
        "dst_port": str(event.dst_port or ""),
        "logdata_message": str(event.logdata.get("message", "")),
        "logdata": logdata,
    }
    fields["combined"] = " ".join(fields.values())
    return {key: value.lower() for key, value in fields.items()}


def _logdata_text(logdata: dict[str, Any]) -> str:
    """Join raw logdata values so Sigma can search payload text consistently."""
    return " ".join(str(value) for value in logdata.values())


def _rule_name(payload: dict[str, Any], path: Path) -> str:
    """Return a stable rule id for observations and debug output."""
    configured_name = payload.get("honeynet.rule_name")
    if isinstance(configured_name, str) and configured_name:
        return configured_name
    raw = str(payload.get("title") or path.stem)
    return re.sub(r"_+", "_", re.sub(r"[^a-zA-Z0-9]+", "_", raw)).strip("_").lower()


def _format_indicator(field: str, marker: str) -> str:
    """Render one matched field/value marker for explainability."""
    return f"{field}:{marker}"
