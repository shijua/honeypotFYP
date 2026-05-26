"""Use compatible Sigma selections as Cowrie command mappings.

Sigma rules describe endpoint telemetry, while Cowrie records attacker-entered
shell text. This module uses the overlap we can observe locally:
process names, command lines, auditd EXECVE arguments, and simple shell
keywords with ATT&CK tags. Runtime detection reads the configured Sigma folder
directly, while the import helpers remain useful for validation and reports.

This is intentionally not a full Sigma engine. The configured folder decides
which Sigma rules are in scope; this code only answers one question for each
selection: can it be evaluated from a single Cowrie command string?
"""

from __future__ import annotations

import re
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from libs.common.iterables import dedupe_preserve_by
from libs.common.sigma import (
    sigma_attack_techniques,
    sigma_files,
    sigma_keyword_to_regex,
    sigma_selection_plans,
    sigma_string_values,
    sigma_values,
    split_sigma_field,
)
from services.cowrie.command_mapping import (
    CommandMatch,
    CowrieCommandRule,
    command_matches_rule,
    normalize_command,
)
from services.cowrie.mapping_utils import lower_strings, source_ref_from_payload, strings


@dataclass(frozen=True)
class SigmaImportResult:
    """Generated Cowrie rules plus counters for tests and health reporting."""

    rules: list[dict[str, object]]
    files_read: int
    files_with_rules: int


class SigmaCowrieCommandRuleCatalog:
    """Runtime catalog backed by Sigma YAML files.

    Rules are loaded lazily from the configured Sigma directory, then converted
    to the same immutable `CowrieCommandRule` objects used by local JSON rules.
    This avoids a generated intermediate file while keeping command matching
    fast after the first command arrives.
    """

    def __init__(self, root: str | Path) -> None:
        self._root = str(root)
        self._loaded = False
        self._rules: tuple[CowrieCommandRule, ...] = ()

    def match(self, command: str) -> tuple[CowrieCommandRule, ...]:
        self._ensure_loaded()
        normalized = normalize_command(command)
        if normalized is None:
            return ()
        return tuple(rule for rule in self._rules if command_matches_rule(normalized, rule))

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return

        # Load once per adapter process. If the Sigma checkout changes on disk,
        # restart the Cowrie adapter so the in-memory catalog is rebuilt.
        result = _import_sigma_command_rules_from_configured_roots(self._root)
        self._rules = tuple(
            dedupe_preserve_by(
                (_cowrie_rule_from_sigma_payload(item) for item in result.rules),
                lambda rule: (rule.name, rule.technique_id),
            )
        )
        self._loaded = True


def _import_sigma_command_rules_from_configured_roots(root: str) -> SigmaImportResult:
    """Load one or more Sigma roots from an `os.pathsep` separated config value.

    Example:
        "data/detections/cowrie_sigma:vendor/sigma/rules/linux" loads both when present, while a missing optional vendor checkout is skipped if the local root exists.
    """
    roots = [Path(item) for item in root.split(os.pathsep) if item]
    if len(roots) <= 1:
        return import_sigma_command_rules(roots[0] if roots else Path(root))

    rules: list[dict[str, object]] = []
    files_read = 0
    files_with_rules = 0
    existing_roots = [path for path in roots if path.exists()]
    if not existing_roots:
        raise FileNotFoundError(f"Sigma rule path does not exist: {root}")

    for path in existing_roots:
        result = import_sigma_command_rules(path)
        rules.extend(result.rules)
        files_read += result.files_read
        files_with_rules += result.files_with_rules

    return SigmaImportResult(
        rules=_dedupe_rule_names(rules),
        files_read=files_read,
        files_with_rules=files_with_rules,
    )


def import_sigma_command_rules(root: Path) -> SigmaImportResult:
    """Load Sigma YAML files and convert compatible rules.

    The configured folder controls scope. Each rule selection is imported when
    it can be expressed from one Cowrie command; unsupported fields and complex
    correlation stay outside this lightweight mapper.
    """
    rules: list[dict[str, object]] = []
    files_read = 0
    files_with_rules = 0

    for path in sigma_files(root):
        files_read += 1
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            continue
        generated = sigma_rule_to_command_rules(payload, path)
        if generated:
            files_with_rules += 1
            rules.extend(generated)

    return SigmaImportResult(
        rules=_dedupe_rule_names(rules),
        files_read=files_read,
        files_with_rules=files_with_rules,
    )


def sigma_rule_to_command_rules(
    payload: dict[str, Any],
    source_path: Path,
) -> list[dict[str, object]]:
    """Convert one Sigma rule payload into zero or more Cowrie mapping rules.

    There is no extra logsource whitelist here. If a rule is in the configured
    folder and a selection can be represented from Cowrie's command text, it is
    eligible. Unsupported selections simply return no generated rule.
    """
    techniques = sigma_attack_techniques(payload.get("tags"))
    if not techniques:
        return []

    detection = payload.get("detection")
    if not isinstance(detection, dict):
        return []

    title = str(payload.get("title") or source_path.stem)
    confidence = _confidence_from_sigma_level(payload.get("level"))
    source_refs = _source_refs(payload, source_path, title)
    generated: list[dict[str, object]] = []

    for plan in sigma_selection_plans(detection):
        positive_matches = _matches_from_selections(plan.positives)
        if len(positive_matches) != len(plan.positives):
            continue

        match = _merge_match_payloads(positive_matches)
        if not match:
            continue

        negative_matches = _matches_from_selections(plan.negatives)
        if len(negative_matches) != len(plan.negatives):
            continue
        exclude_match = _merge_or_match_payloads(negative_matches) if negative_matches else None

        for technique_id in techniques:
            rule = {
                "name": _rule_name(title, plan.name, technique_id),
                "technique_id": technique_id,
                "confidence": confidence,
                "match": match,
                "source_refs": source_refs,
            }
            if exclude_match:
                rule["exclude_match"] = exclude_match
            generated.append(rule)

    return generated


def _matches_from_selections(selections: tuple[object, ...]) -> list[dict[str, list[str]]]:
    """Convert selections to match payloads without weakening unsupported ones."""
    matches: list[dict[str, list[str]]] = []
    for selection in selections:
        match = _match_from_sigma_selection(selection)
        if match:
            matches.append(match)
    return matches


def _cowrie_rule_from_sigma_payload(payload: dict[str, object]) -> CowrieCommandRule:
    match_payload = payload.get("match", {})
    if not isinstance(match_payload, dict):
        match_payload = {}
    return CowrieCommandRule(
        name=str(payload.get("name", "sigma_rule")),
        technique_id=str(payload.get("technique_id", "")),
        confidence=str(payload.get("confidence", "medium")),
        match=CommandMatch(
            process_names=tuple(lower_strings(match_payload.get("process_names", []))),
            command_line_contains_any=tuple(
                lower_strings(match_payload.get("command_line_contains_any", []))
            ),
            command_line_regex_any=tuple(
                strings(match_payload.get("command_line_regex_any", []))
            ),
        ),
        source_refs=tuple(
            source_ref_from_payload(item)
            for item in payload.get("source_refs", [])
            if isinstance(item, dict)
        ),
        exclude_match=_optional_match_from_sigma_payload(payload.get("exclude_match")),
    )


def _optional_match_from_sigma_payload(payload: object) -> CommandMatch | None:
    """Convert optional Sigma exclude-match payloads into runtime match objects."""
    if not isinstance(payload, dict):
        return None
    return CommandMatch(
        process_names=tuple(lower_strings(payload.get("process_names", []))),
        command_line_contains_any=tuple(
            lower_strings(payload.get("command_line_contains_any", []))
        ),
        command_line_regex_any=tuple(
            strings(payload.get("command_line_regex_any", []))
        ),
    )


def _match_from_sigma_selection(selection: object) -> dict[str, list[str]]:
    """Translate one compatible Sigma selection into CommandMatch JSON.

    Supported shapes:
    - keyword lists, such as `keywords: ["history -c", "rm *sh_history"]`
    - process fields, such as `Image|endswith: /curl`
    - command-line fields, such as `CommandLine|contains: /etc/passwd`
    - auditd EXECVE args, such as `type: EXECVE`, `a0: chmod`, `a1: 777`

    Any unsupported field makes the whole selection return `{}`. That avoids
    partial matches where a Sigma rule needs context Cowrie does not have.
    """
    keyword_regexes = _keyword_regexes(selection)
    if keyword_regexes:
        return {"command_line_regex_any": keyword_regexes}
    if not isinstance(selection, dict):
        return {}

    process_names: list[str] = []
    contains_any: list[str] = []
    regex_any: list[str] = []
    required_arg_groups: list[list[str]] = []

    for raw_field, raw_value in selection.items():
        field, modifiers = split_sigma_field(str(raw_field))
        values = sigma_values(raw_value)
        if not values:
            return {}

        if field == "type":
            if "execve" in values:
                continue
            return {}

        # auditd EXECVE records split command execution into a0/a1/a2...
        # Cowrie stores the shell line, so a0 becomes the process name and the
        # remaining args become required command-line lookaheads.
        if _is_auditd_arg_field(field):
            index = int(field[1:])
            if index == 0:
                process_names.extend(_process_names_from_values(values))
            else:
                required_arg_groups.append(values)
            continue

        if _is_process_name_field(field):
            process_names.extend(_process_names_from_values(values))
            continue

        if not _is_command_line_field(field):
            return {}

        if "contains" in modifiers and "all" in modifiers:
            regex_any.append(_contains_all_regex(values))
        elif "contains" in modifiers:
            contains_any.extend(value.lower() for value in values)
        elif "re" in modifiers or "regex" in modifiers:
            regex_any.extend(_case_insensitive_regex(value) for value in values)
        elif "startswith" in modifiers:
            regex_any.extend(f"^{re.escape(value.lower())}" for value in values)
        elif "endswith" in modifiers:
            regex_any.extend(f"{re.escape(value.lower())}$" for value in values)
        elif not modifiers:
            regex_any.extend(f"^{re.escape(value.lower())}$" for value in values)
        else:
            return {}

    if required_arg_groups:
        regex_any.append(_contains_each_group_regex(required_arg_groups))

    match: dict[str, list[str]] = {}
    if process_names:
        match["process_names"] = sorted(set(process_names))
    if contains_any:
        match["command_line_contains_any"] = sorted(set(contains_any))
    if regex_any:
        match["command_line_regex_any"] = sorted(set(regex_any))
    return match


def _merge_match_payloads(matches: list[dict[str, list[str]]]) -> dict[str, list[str]]:
    """Merge Sigma AND selections into one command match payload.

    Process-name constraints are intersected because a command has only one
    process name. Command-line groups are combined into a single lookahead regex
    when more than one group must be true.
    """
    process_names: set[str] | None = None
    contains_groups: list[list[str]] = []
    regex_groups: list[list[str]] = []

    for match in matches:
        names = set(match.get("process_names", []))
        if names:
            process_names = names if process_names is None else process_names & names
            if not process_names:
                return {}

        contains = match.get("command_line_contains_any", [])
        if contains:
            contains_groups.append(contains)

        regexes = match.get("command_line_regex_any", [])
        if regexes:
            regex_groups.append(regexes)

    merged: dict[str, list[str]] = {}
    if process_names:
        merged["process_names"] = sorted(process_names)

    if len(contains_groups) == 1 and not regex_groups:
        merged["command_line_contains_any"] = sorted(set(contains_groups[0]))
    elif contains_groups or regex_groups:
        merged["command_line_regex_any"] = [
            _combined_command_line_regex(contains_groups, regex_groups)
        ]

    return merged


def _merge_or_match_payloads(matches: list[dict[str, list[str]]]) -> dict[str, list[str]]:
    """Merge simple filter matches so any filter hit can suppress a rule.

    This is intentionally only used for one-filter branches today. The OR merge
    still handles repeated values defensively without changing the public model.
    """
    process_names: list[str] = []
    contains_any: list[str] = []
    regex_any: list[str] = []
    for match in matches:
        process_names.extend(match.get("process_names", []))
        contains_any.extend(match.get("command_line_contains_any", []))
        regex_any.extend(match.get("command_line_regex_any", []))

    merged: dict[str, list[str]] = {}
    if process_names:
        merged["process_names"] = sorted(set(process_names))
    if contains_any:
        merged["command_line_contains_any"] = sorted(set(contains_any))
    if regex_any:
        merged["command_line_regex_any"] = sorted(set(regex_any))
    return merged


def _combined_command_line_regex(
    contains_groups: list[list[str]],
    regex_groups: list[list[str]],
) -> str:
    """Build one regex that requires every command-line condition group."""
    parts: list[str] = []
    for values in contains_groups:
        options = [re.escape(value.lower()) for value in values if value]
        if options:
            parts.append(f"(?=.*(?:{'|'.join(options)}))")
    for patterns in regex_groups:
        options = [_regex_option(pattern) for pattern in patterns if pattern]
        if options:
            parts.append(f"(?=.*(?:{'|'.join(options)}))")
    return "".join(parts)


def _regex_option(pattern: str) -> str:
    """Make a Sigma regex safe to embed inside a larger lookahead regex."""
    if pattern.startswith("(?i)"):
        return f"(?i:{pattern[4:]})"
    return pattern


def _is_process_name_field(field: str) -> bool:
    return field in {"image", "process_name", "process_executable"}


def _is_command_line_field(field: str) -> bool:
    return field in {"commandline", "command_line", "process_command_line", "cmdline"}


def _is_auditd_arg_field(field: str) -> bool:
    return bool(re.fullmatch(r"a\d+", field))


def _process_names_from_values(values: list[str]) -> list[str]:
    """Convert `/usr/bin/curl`, `*\\whoami.exe`, or `nmap` to process names."""
    names: list[str] = []
    for value in values:
        clean_value = value.strip("*").replace("\\", "/")
        process_name = clean_value.rsplit("/", 1)[-1].lower()
        if process_name.endswith(".exe"):
            process_name = process_name[:-4]
        if process_name:
            names.append(process_name)
    return names


def _contains_all_regex(values: list[str]) -> str:
    """Build one regex that requires all Sigma `contains|all` fragments."""
    return "".join(f"(?=.*{re.escape(value.lower())})" for value in values)


def _contains_each_group_regex(value_groups: list[list[str]]) -> str:
    """Build one regex that requires one value from each EXECVE arg group."""
    parts: list[str] = []
    for values in value_groups:
        options = [re.escape(value.lower()) for value in values if value]
        if not options:
            continue
        parts.append(f"(?=.*(?:{'|'.join(options)}))")
    return "".join(parts)


def _keyword_regexes(selection: object) -> list[str]:
    """Convert Sigma keyword lists into command-line regexes."""
    values = sigma_string_values(selection)
    if not values:
        return []
    return [sigma_keyword_to_regex(value) for value in values]


def _case_insensitive_regex(value: str) -> str:
    return value if value.startswith("(?i)") else f"(?i){value}"


def _confidence_from_sigma_level(level: object) -> str:
    value = str(level or "medium").lower()
    if value in {"critical", "high"}:
        return "high"
    if value == "medium":
        return "medium"
    return "low"


def _source_refs(
    payload: dict[str, Any],
    source_path: Path,
    title: str,
) -> list[dict[str, object]]:
    references = sigma_string_values(payload.get("references"))
    return [
        {
            "type": "sigma_rule",
            "name": title,
            "url": references[0] if references else None,
        },
        {
            "type": "sigma_rule_file",
            "name": str(source_path),
        },
    ]


def _rule_name(title: str, selection_name: str, technique_id: str) -> str:
    raw = f"{title}_{selection_name}_{technique_id}"
    return re.sub(r"_+", "_", re.sub(r"[^a-zA-Z0-9]+", "_", raw)).strip("_").lower()


def _dedupe_rule_names(rules: list[dict[str, object]]) -> list[dict[str, object]]:
    """Keep generated rule names unique for the strict mapping validator."""
    seen: dict[str, int] = {}
    deduped: list[dict[str, object]] = []
    for rule in rules:
        name = str(rule.get("name", "sigma_rule"))
        count = seen.get(name, 0)
        seen[name] = count + 1
        if count == 0:
            deduped.append(rule)
            continue

        updated_rule = dict(rule)
        updated_rule["name"] = f"{name}_{count + 1}"
        deduped.append(updated_rule)
    return deduped
