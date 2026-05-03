"""Sigma-backed matcher for public and internal HTTP telemetry.

This is a small HTTP-specific Sigma subset. It reads normal Sigma YAML files,
then evaluates selections against the normalized fields that the entrypoint
actually observes: method, path, query string, user-agent, body preview, surface,
asset id, and a combined request string.
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
from services.entrypoint.rule_matcher import PublicHttpRuleMatch, PublicHttpRuleMatcher


DEFAULT_HTTP_SIGMA_RULES_PATH = Path("data/detections/http_sigma")

FIELD_ALIASES = {
    "method": "method",
    "http_method": "method",
    "http.request.method": "method",
    "http_request_method": "method",
    "request_method": "method",
    "url.path": "path",
    "url_path": "path",
    "uri_path": "path",
    "cs_uri_stem": "path",
    "query_string": "query_string",
    "url.query": "query_string",
    "url_query": "query_string",
    "cs_uri_query": "query_string",
    "body": "body_preview",
    "body_preview": "body_preview",
    "http.request.body.content": "body_preview",
    "http_request_body_content": "body_preview",
    "user_agent": "user_agent",
    "http.user_agent": "user_agent",
    "http_user_agent": "user_agent",
    "user_agent.original": "user_agent",
    "user_agent_original": "user_agent",
    "url.original": "combined",
    "url_original": "combined",
    "request": "combined",
    "request_uri": "combined",
    "http.url": "combined",
    "http_url": "combined",
    "combined": "combined",
    "honeynet.surface": "surface",
    "honeynet_surface": "surface",
    "surface": "surface",
    "honeynet.asset_id": "asset_id",
    "honeynet_asset_id": "asset_id",
    "asset_id": "asset_id",
}


@dataclass(frozen=True)
class SigmaHttpRule:
    """One HTTP Sigma rule prepared for runtime matching."""

    name: str
    tags: tuple[str, ...]
    evidence_label: str | None
    plans: tuple[SigmaSelectionPlan, ...]


class FilePublicHttpSigmaRuleMatcher:
    """Load HTTP Sigma YAML files and match them against one HTTP event."""

    def __init__(self, path: str | Path = DEFAULT_HTTP_SIGMA_RULES_PATH) -> None:
        self._path = Path(path)
        self._rules: tuple[SigmaHttpRule, ...] | None = None

    def tags_for(
        self,
        *,
        method: str,
        path: str,
        query_string: str = "",
        body_preview: str | None = None,
        user_agent: str | None = None,
        surface: str = "public",
        asset_id: str | None = None,
    ) -> list[str]:
        matches = self.matches_for(
            method=method,
            path=path,
            query_string=query_string,
            body_preview=body_preview,
            user_agent=user_agent,
            surface=surface,
            asset_id=asset_id,
        )
        tags: list[str] = []
        for match in matches:
            for tag in match.tags:
                if tag not in tags:
                    tags.append(tag)
        return tags

    def matches_for(
        self,
        *,
        method: str,
        path: str,
        query_string: str = "",
        body_preview: str | None = None,
        user_agent: str | None = None,
        surface: str = "public",
        asset_id: str | None = None,
    ) -> list[PublicHttpRuleMatch]:
        fields = _normalize_http_fields(
            method=method,
            path=path,
            query_string=query_string,
            body_preview=body_preview,
            user_agent=user_agent,
            surface=surface,
            asset_id=asset_id,
        )
        matches: list[PublicHttpRuleMatch] = []
        for rule in self._load_rules():
            indicators = _rule_indicators(rule, fields)
            if not indicators:
                continue
            matches.append(
                PublicHttpRuleMatch(
                    rule_name=rule.name,
                    tags=rule.tags,
                    indicators=tuple(dedupe_preserve(indicators)),
                    evidence_label=rule.evidence_label,
                )
            )
        return matches

    def _load_rules(self) -> tuple[SigmaHttpRule, ...]:
        if self._rules is not None:
            return self._rules
        self._rules = tuple(
            rule
            for path in sigma_files(self._path, label="HTTP Sigma rule path")
            if (rule := _rule_from_sigma_file(path)) is not None
        )
        return self._rules


def _rule_from_sigma_file(path: Path) -> SigmaHttpRule | None:
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
    return SigmaHttpRule(
        name=_rule_name(payload, path),
        tags=tuple(tags),
        evidence_label=_evidence_label(payload),
        plans=plans,
    )


def _rule_indicators(rule: SigmaHttpRule, fields: dict[str, str]) -> list[str]:
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
    combined = fields["combined"]
    indicators: list[str] = []
    for value in selection:
        if not isinstance(value, str) or not value:
            continue
        if re.search(sigma_keyword_to_regex(value), combined):
            indicators.append(_format_indicator("combined", value))
    return indicators


def _normalize_http_fields(
    *,
    method: str,
    path: str,
    query_string: str,
    body_preview: str | None,
    user_agent: str | None,
    surface: str,
    asset_id: str | None,
) -> dict[str, str]:
    fields = {
        "method": method,
        "path": path,
        "query_string": query_string,
        "body_preview": body_preview or "",
        "user_agent": user_agent or "",
        "surface": surface,
        "asset_id": asset_id or "",
    }
    fields["combined"] = " ".join(fields.values())
    return {key: value.lower() for key, value in fields.items()}


def _rule_name(payload: dict[str, Any], path: Path) -> str:
    configured_name = payload.get("honeynet.rule_name")
    if isinstance(configured_name, str) and configured_name:
        return configured_name
    raw = str(payload.get("title") or path.stem)
    return re.sub(r"_+", "_", re.sub(r"[^a-zA-Z0-9]+", "_", raw)).strip("_").lower()


def _evidence_label(payload: dict[str, Any]) -> str | None:
    label = payload.get("honeynet.evidence_label")
    return label if isinstance(label, str) and label else None


def _format_indicator(field: str, marker: str) -> str:
    return f"{field}:{marker}"
