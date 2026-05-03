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
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Any

import yaml

from libs.common.iterables import dedupe_preserve_by
from services.cowrie.command_mapping import (
    CommandMatch,
    CowrieCommandRule,
    SourceRef,
    command_matches_rule,
    normalize_command,
)


SUPPORTED_SUFFIXES = {".yml", ".yaml"}


@dataclass(frozen=True)
class SigmaImportResult:
    """Generated Cowrie rules plus counters for tests and health reporting."""

    rules: list[dict[str, object]]
    files_read: int
    files_with_rules: int


@dataclass(frozen=True)
class SigmaSelectionPlan:
    """One generated rule plan from a Sigma condition branch.

    `positives` are compatible selections that must all match the command.
    `negatives` are filter selections from `and not filter_*`; when a negative
    selection matches, the generated rule is suppressed.
    """

    name: str
    positives: tuple[object, ...]
    negatives: tuple[object, ...] = ()


class SigmaCowrieCommandRuleCatalog:
    """Runtime catalog backed by Sigma YAML files.

    Rules are loaded lazily from the configured Sigma directory, then converted
    to the same immutable `CowrieCommandRule` objects used by local JSON rules.
    This avoids a generated intermediate file while keeping command matching
    fast after the first command arrives.
    """

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
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
        result = import_sigma_command_rules(self._root)
        self._rules = tuple(
            dedupe_preserve_by(
                (_cowrie_rule_from_sigma_payload(item) for item in result.rules),
                lambda rule: (rule.name, rule.technique_id),
            )
        )
        self._loaded = True


def import_sigma_command_rules(root: Path) -> SigmaImportResult:
    """Load Sigma YAML files and convert compatible rules.

    The configured folder controls scope. Each rule selection is imported when
    it can be expressed from one Cowrie command; unsupported fields and complex
    correlation stay outside this lightweight mapper.
    """
    rules: list[dict[str, object]] = []
    files_read = 0
    files_with_rules = 0

    for path in _sigma_files(root):
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
    techniques = _attack_techniques(payload.get("tags"))
    if not techniques:
        return []

    detection = payload.get("detection")
    if not isinstance(detection, dict):
        return []

    title = str(payload.get("title") or source_path.stem)
    confidence = _confidence_from_sigma_level(payload.get("level"))
    source_refs = _source_refs(payload, source_path, title)
    generated: list[dict[str, object]] = []

    for plan in _selection_plans(detection):
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


def _sigma_files(root: Path) -> list[Path]:
    """Return Sigma YAML files in deterministic order."""
    if not root.exists():
        raise FileNotFoundError(f"Sigma rule path does not exist: {root}")
    if root.is_file():
        return [root] if root.suffix.lower() in SUPPORTED_SUFFIXES else []
    return sorted(path for path in root.rglob("*") if path.suffix.lower() in SUPPORTED_SUFFIXES)


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
            process_names=tuple(_lower_strings(match_payload.get("process_names", []))),
            command_line_contains_any=tuple(
                _lower_strings(match_payload.get("command_line_contains_any", []))
            ),
            command_line_regex_any=tuple(
                _strings(match_payload.get("command_line_regex_any", []))
            ),
        ),
        source_refs=tuple(
            _source_ref_from_sigma_payload(item)
            for item in payload.get("source_refs", [])
            if isinstance(item, dict)
        ),
        exclude_match=_optional_match_from_sigma_payload(payload.get("exclude_match")),
    )


def _source_ref_from_sigma_payload(payload: dict[str, object]) -> SourceRef:
    url = payload.get("url")
    return SourceRef(
        type=str(payload.get("type", "")),
        name=str(payload.get("name", "")),
        url=str(url) if url is not None else None,
    )


def _optional_match_from_sigma_payload(payload: object) -> CommandMatch | None:
    """Convert optional Sigma exclude-match payloads into runtime match objects."""
    if not isinstance(payload, dict):
        return None
    return CommandMatch(
        process_names=tuple(_lower_strings(payload.get("process_names", []))),
        command_line_contains_any=tuple(
            _lower_strings(payload.get("command_line_contains_any", []))
        ),
        command_line_regex_any=tuple(
            _strings(payload.get("command_line_regex_any", []))
        ),
    )


def _lower_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).lower() for item in value]


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _attack_techniques(tags: object) -> list[str]:
    """Extract ATT&CK technique IDs from Sigma tags such as attack.t1105."""
    if not isinstance(tags, list):
        return []

    techniques: list[str] = []
    for tag in tags:
        value = str(tag).lower()
        match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", value)
        if match:
            techniques.append(match.group(1).upper())
    return sorted(set(techniques))


def _selection_plans(detection: dict[str, Any]) -> list[SigmaSelectionPlan]:
    """Return rule plans that preserve the simple Sigma condition subset.

    Supported condition shapes:
    - `selection`
    - `selection_a or selection_b`
    - `selection_a and selection_b`
    - `all of selection_*`
    - `1 of selection_*`
    - `selection and not filter`

    Anything more complex returns no plan. That keeps the mapper conservative:
    it may miss some Sigma rules, but it should not turn a stricter Sigma rule
    into a noisier Cowrie match.
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


def _plans_from_and_branch(
    branch: str,
    selections: dict[str, object],
) -> list[SigmaSelectionPlan]:
    """Build one or more plans from a branch without top-level OR."""
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
        positive_names = tuple(
            dedupe_preserve_by(
                (name for option in option_group for name in option),
                lambda name: name,
            )
        )
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
    """Return AND groups or OR options for one positive condition term."""
    if term.startswith("1 of "):
        names = _selection_names_for_term(
            term.removeprefix("1 of ").strip(),
            selections,
            include_filters=False,
        )
        return [[name] for name in names]
    return [
        _selection_names_for_term(term, selections, include_filters=False)
    ]


def _selection_names_for_term(
    term: str,
    selections: dict[str, object],
    *,
    include_filters: bool,
) -> list[str]:
    """Expand one Sigma condition term to concrete detection selection names."""
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
    """Resolve exact names, `them`, or wildcard prefixes such as `selection_*`."""
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
    """Return detection entries that can represent Sigma selections or filters."""
    return {
        str(name).lower(): value
        for name, value in detection.items()
        if str(name).lower() != "condition" and isinstance(value, (dict, list))
    }


def _normalize_condition(condition: str) -> str:
    """Normalize the simple condition grammar supported by this mapper."""
    return " ".join(condition.lower().replace("(", " ").replace(")", " ").split())


def _is_filter_name(name: str) -> bool:
    return "filter" in name


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
        field, modifiers = _split_sigma_field(str(raw_field))
        values = _sigma_values(raw_value)
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


def _split_sigma_field(raw_field: str) -> tuple[str, set[str]]:
    """Split `CommandLine|contains|all` into field name plus modifiers."""
    parts = [part.strip() for part in raw_field.split("|") if part.strip()]
    if not parts:
        return "", set()
    return parts[0].replace(".", "_").lower(), {part.lower() for part in parts[1:]}


def _is_process_name_field(field: str) -> bool:
    return field in {"image", "process_name", "process_executable"}


def _is_command_line_field(field: str) -> bool:
    return field in {"commandline", "command_line", "process_command_line", "cmdline"}


def _is_auditd_arg_field(field: str) -> bool:
    return bool(re.fullmatch(r"a\d+", field))


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item]
    return []


def _sigma_values(value: Any) -> list[str]:
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
    values = _string_values(selection)
    if not values:
        return []
    return [_sigma_keyword_to_regex(value) for value in values]


def _sigma_keyword_to_regex(value: str) -> str:
    """Convert Sigma wildcard `*` in keyword strings to regex wildcards."""
    parts = [re.escape(part.lower()) for part in value.split("*")]
    return ".*".join(parts)


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
    references = _string_values(payload.get("references"))
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
