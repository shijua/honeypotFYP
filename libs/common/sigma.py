"""Shared helpers for the small Sigma subset used by honeynet services."""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Any

from libs.common.iterables import dedupe_preserve


SUPPORTED_SIGMA_SUFFIXES = {".yml", ".yaml"}


@dataclass(frozen=True)
class SigmaSelectionPlan:
    """One supported branch of a Sigma detection condition."""

    name: str
    positives: tuple[object, ...]
    negatives: tuple[object, ...] = ()


def sigma_files(root: Path, *, label: str = "Sigma rule path") -> list[Path]:
    """Return Sigma YAML files in deterministic order."""
    if not root.exists():
        raise FileNotFoundError(f"{label} does not exist: {root}")
    if root.is_file():
        return [root] if root.suffix.lower() in SUPPORTED_SIGMA_SUFFIXES else []
    return sorted(path for path in root.rglob("*") if path.suffix.lower() in SUPPORTED_SIGMA_SUFFIXES)


def sigma_selection_plans(detection: dict[str, Any]) -> list[SigmaSelectionPlan]:
    """Expand the conservative Sigma condition grammar shared by runtime mappers.

    Supported condition shapes are standalone selections, top-level OR, AND, `1 of selection_*`, `all of selection_*`, and `selection and not filter_*`. Unsupported condition shapes return no plan, so callers can skip rules instead of weakening them.
    """
    selections = _named_selections(detection)
    condition = _normalize_condition(str(detection.get("condition", "")))
    if not condition:
        return [
            SigmaSelectionPlan(name=name, positives=(selection,))
            for name, selection in selections.items()
            if not _is_filter_name(name)
        ]

    plans: list[SigmaSelectionPlan] = []
    for branch in re.split(r"\s+or\s+", condition):
        plans.extend(_plans_from_and_branch(branch, selections))
    return plans


def split_sigma_field(raw_field: str) -> tuple[str, set[str]]:
    """Split `Field|contains|all` into normalized field name plus modifiers."""
    parts = [part.strip() for part in raw_field.split("|") if part.strip()]
    if not parts:
        return "", set()
    return parts[0].replace(".", "_").lower(), {part.lower() for part in parts[1:]}


def sigma_values(value: Any) -> list[str]:
    """Normalize scalar/list Sigma values to lowercase strings."""
    if isinstance(value, (str, int, float)):
        return [str(value).lower()]
    if isinstance(value, list):
        return [
            str(item).lower()
            for item in value
            if isinstance(item, (str, int, float)) and str(item)
        ]
    return []


def sigma_string_values(value: Any) -> list[str]:
    """Return only non-empty string values from a scalar/list Sigma field."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item]
    return []


def sigma_attack_techniques(tags: object) -> list[str]:
    """Extract ATT&CK technique IDs from Sigma tags such as `attack.t1105`."""
    if not isinstance(tags, list):
        return []

    techniques: list[str] = []
    for tag in tags:
        value = str(tag).lower()
        match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", value)
        if match:
            techniques.append(match.group(1).upper())
    return sorted(set(techniques))


def sigma_attack_profile_tags(tags: object) -> list[str]:
    """Convert Sigma ATT&CK tags into profiler tags such as `mitre_discovery`."""
    if not isinstance(tags, list):
        return []

    output: list[str] = []
    for tag in tags:
        value = str(tag).lower()
        technique = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", value)
        if technique:
            output.append(technique.group(1).upper())
            continue
        tactic = re.fullmatch(r"attack\.([a-z_-]+)", value)
        if tactic:
            output.append(f"mitre_{tactic.group(1).replace('-', '_')}")
    return dedupe_preserve(output)


def sigma_keyword_to_regex(value: str) -> str:
    """Convert Sigma wildcard `*` in keyword strings to regex wildcards."""
    parts = [re.escape(part.lower()) for part in value.split("*")]
    return ".*".join(parts)


def _plans_from_and_branch(
    branch: str,
    selections: dict[str, object],
) -> list[SigmaSelectionPlan]:
    positive_options: list[list[list[str]]] = []
    negatives: list[str] = []

    for term in re.split(r"\s+and\s+", branch):
        term = term.strip()
        if not term:
            return []
        if term.startswith("not "):
            negative_names = _selection_names_for_term(
                term.removeprefix("not ").strip(),
                selections,
                include_filters=True,
            )
            if len(negative_names) != 1:
                return []
            negatives.extend(negative_names)
            continue

        options = _positive_name_options_for_term(term, selections)
        if not options:
            return []
        positive_options.append(options)

    if not positive_options:
        return []

    plans: list[SigmaSelectionPlan] = []
    for option_group in product(*positive_options):
        positive_names = tuple(dedupe_preserve(name for option in option_group for name in option))
        if not positive_names:
            continue
        name = "_and_".join((*positive_names, *negatives))
        plans.append(
            SigmaSelectionPlan(
                name=name,
                positives=tuple(selections[item] for item in positive_names),
                negatives=tuple(selections[item] for item in negatives),
            )
        )
    return plans


def _positive_name_options_for_term(
    term: str,
    selections: dict[str, object],
) -> list[list[str]]:
    if term.startswith("1 of "):
        names = _selection_names_for_term(
            term.removeprefix("1 of ").strip(),
            selections,
            include_filters=False,
        )
        return [[name] for name in names]
    return [_selection_names_for_term(term, selections, include_filters=False)]


def _selection_names_for_term(
    term: str,
    selections: dict[str, object],
    *,
    include_filters: bool,
) -> list[str]:
    if term.startswith("all of "):
        return _selection_names_for_pattern(
            term.removeprefix("all of ").strip(),
            selections,
            include_filters=include_filters,
        )
    if term.startswith("1 of "):
        return _selection_names_for_pattern(
            term.removeprefix("1 of ").strip(),
            selections,
            include_filters=include_filters,
        )
    return _selection_names_for_pattern(term, selections, include_filters=include_filters)


def _selection_names_for_pattern(
    pattern: str,
    selections: dict[str, object],
    *,
    include_filters: bool,
) -> list[str]:
    names = list(selections)
    if not include_filters:
        names = [name for name in names if not _is_filter_name(name)]

    if pattern == "them":
        return names
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return [name for name in names if name.startswith(prefix)]
    return [pattern] if pattern in names and (include_filters or not _is_filter_name(pattern)) else []


def _named_selections(detection: dict[str, Any]) -> dict[str, object]:
    return {
        str(name).lower(): value
        for name, value in detection.items()
        if str(name).lower() != "condition" and isinstance(value, (dict, list))
    }


def _normalize_condition(condition: str) -> str:
    return " ".join(condition.lower().replace("(", " ").replace(")", " ").split())


def _is_filter_name(name: str) -> bool:
    return "filter" in name
