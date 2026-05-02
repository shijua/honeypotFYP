"""Rule matcher for HTTP detection evidence.

The matcher keeps web detection content in JSON so entrypoint code does
not grow a hard-coded list of scanner paths and user-agent strings. Matching
rules return both profiler tags and human-readable indicators for the dashboard.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Protocol

from libs.common.iterables import dedupe_preserve


DEFAULT_PUBLIC_HTTP_RULES_PATH = Path("data/detections/public_http_rules.json")


class PublicHttpRuleMatcher(Protocol):
    """Contract for turning normalized HTTP fields into detection evidence."""

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
    ) -> list["PublicHttpRuleMatch"]:
        """Return detailed rule matches for one HTTP event."""
        ...

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
        """Return de-duplicated profiler tags from the matching rules."""
        ...


@dataclass(frozen=True)
class PublicHttpDetectionRule:
    """One JSON-backed HTTP detection rule."""

    name: str
    tags: tuple[str, ...]
    match: Mapping[str, Any]
    evidence_label: str | None = None


@dataclass(frozen=True)
class PublicHttpRuleMatch:
    """Detailed match output used as profiler/dashboard evidence."""

    rule_name: str
    tags: tuple[str, ...]
    indicators: tuple[str, ...]
    evidence_label: str | None = None


class FilePublicHttpRuleMatcher:
    """Load HTTP rules from disk and match them against request fields."""

    def __init__(self, path: str | Path = DEFAULT_PUBLIC_HTTP_RULES_PATH) -> None:
        self._path = Path(path)
        self._rules: tuple[PublicHttpDetectionRule, ...] | None = None

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
        """Return tags from all matching rules, preserving rule order."""
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
        """Return matching rule names, tags, and concrete indicators."""
        fields = _normalize_fields(
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
            if not _rule_applies_to_surface(rule.name, surface):
                continue
            indicators = _matched_indicators(rule.match, fields)
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

    def _load_rules(self) -> tuple[PublicHttpDetectionRule, ...]:
        if self._rules is not None:
            return self._rules
        payload = json.loads(self._path.read_text(encoding="utf-8"))
        raw_rules = payload.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError(f"{self._path} must contain a rules list")
        self._rules = tuple(_parse_rule(item, index) for index, item in enumerate(raw_rules))
        return self._rules


def _parse_rule(item: object, index: int) -> PublicHttpDetectionRule:
    if not isinstance(item, dict):
        raise ValueError(f"public HTTP rule {index} must be an object")
    name = item.get("name")
    tags = item.get("tags")
    match = item.get("match")
    if not isinstance(name, str) or not name:
        raise ValueError(f"public HTTP rule {index} missing name")
    if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
        raise ValueError(f"public HTTP rule {name} must contain string tags")
    if not isinstance(match, dict):
        raise ValueError(f"public HTTP rule {name} must contain a match object")
    evidence_label = item.get("evidence_label")
    if evidence_label is not None and not isinstance(evidence_label, str):
        raise ValueError(f"public HTTP rule {name} evidence_label must be a string")
    return PublicHttpDetectionRule(
        name=name,
        tags=tuple(tags),
        match=match,
        evidence_label=evidence_label,
    )


def _normalize_fields(
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


def _matched_indicators(
    condition: Mapping[str, Any],
    fields: Mapping[str, str],
) -> list[str]:
    if "all" in condition:
        children = condition["all"]
        if not isinstance(children, list):
            return []
        indicators: list[str] = []
        for child in children:
            if not isinstance(child, dict):
                return []
            child_indicators = _matched_indicators(child, fields)
            if not child_indicators:
                return []
            indicators.extend(child_indicators)
        return indicators
    if "any" in condition:
        children = condition["any"]
        if not isinstance(children, list):
            return []
        indicators = []
        for child in children:
            if isinstance(child, dict):
                indicators.extend(_matched_indicators(child, fields))
        return indicators

    field = condition.get("field")
    if not isinstance(field, str) or field not in fields:
        return []
    value = fields[field]

    contains_any = condition.get("contains_any")
    if isinstance(contains_any, list):
        indicators = [
            _format_indicator(field, marker)
            for marker in contains_any
            if isinstance(marker, str) and marker.lower() in value
        ]
        if indicators:
            return indicators

    endswith_any = condition.get("endswith_any")
    if isinstance(endswith_any, list):
        indicators = [
            _format_indicator(field, suffix)
            for suffix in endswith_any
            if isinstance(suffix, str) and value.endswith(suffix.lower())
        ]
        if indicators:
            return indicators

    equals_any = condition.get("equals_any")
    if isinstance(equals_any, list):
        indicators = [
            _format_indicator(field, candidate)
            for candidate in equals_any
            if isinstance(candidate, str) and value == candidate.lower()
        ]
        if indicators:
            return indicators

    return []


def _format_indicator(field: str, marker: str) -> str:
    return f"{field}:{marker}"


def _rule_applies_to_surface(rule_name: str, surface: str) -> bool:
    """Keep internal-asset rules from matching public traffic and vice versa."""
    is_internal_rule = rule_name.startswith("internal_http_")
    if surface == "internal":
        return is_internal_rule
    return not is_internal_rule
