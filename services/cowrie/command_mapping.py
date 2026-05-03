"""Command-to-ATT&CK mapping for Cowrie shell input.

Cowrie only gives us the attacker-entered command line, not full endpoint
telemetry. This module normalizes that command into a small process-like event
and applies the selected command mapping catalog. A catalog can be a local JSON
file, a runtime Sigma catalog, or a combination of both.

Example:
    "cat /etc/passwd" -> process_name="cat" -> rule "local_account_file_discovery"
    -> ATT&CK technique T1087.001.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from libs.common.iterables import dedupe_preserve_by


@dataclass(frozen=True)
class SourceRef:
    """External reference used to justify a command mapping rule.

    The mapper does not use this at runtime for matching. It is stored with the
    rule so we can explain why a command pattern maps to a specific technique.

    Example:
        SourceRef(
            type="elastic_detection_rule",
            name="Sensitive Keys...",
            url="https://...",
        )
    """

    type: str
    name: str
    url: str | None = None


@dataclass(frozen=True)
class CommandMatch:
    """Structured match conditions supported by the Cowrie command mapper.

    Values inside one condition are OR-ed, while different conditions are
    AND-ed together.

    Example:
        process_names=("grep", "cat")
        command_line_contains_any=("id_rsa", "password")

    This matches "grep id_rsa /tmp/x" because process_name is grep and the
    command line contains id_rsa. It does not match "echo id_rsa" because the
    process name is not grep or cat.
    """

    process_names: tuple[str, ...] = ()
    command_line_contains_any: tuple[str, ...] = ()
    command_line_regex_any: tuple[str, ...] = ()


@dataclass(frozen=True)
class CowrieCommandRule:
    """Reviewed command-level mapping from Cowrie command input to ATT&CK.

    A rule is intentionally small and auditable: one ATT&CK technique, one
    confidence label, one positive match, optional exclusions, and one or more
    references. Exclusions are used by Sigma `and not filter_*` conditions.

    Example:
        CowrieCommandRule(
            name="credential_file_search",
            technique_id="T1552.001",
            confidence="high",
            match=CommandMatch(process_names=("grep",), command_line_contains_any=("id_rsa",)),
            source_refs=(SourceRef(type="elastic_detection_rule", name="..."),),
        )
    """

    name: str
    technique_id: str
    confidence: str
    match: CommandMatch
    source_refs: tuple[SourceRef, ...]
    exclude_match: CommandMatch | None = None


@dataclass(frozen=True)
class NormalizedCommand:
    """Small process-like view of a command typed into Cowrie.

    Cowrie sees text, but our rules are easier to write against a normalized
    process name plus lower-cased command line.

    Example:
        normalize_command("cat /etc/passwd") ->
        NormalizedCommand(
            command_line="cat /etc/passwd",
            process_name="cat",
            args=("/etc/passwd",),
        )
    """

    command_line: str
    process_name: str
    args: tuple[str, ...]


class CowrieCommandRuleCatalog(Protocol):
    """Lookup contract for command-level ATT&CK mappings.

    CowrieService depends on this protocol instead of a concrete JSON loader, so
    tests can inject an empty or fake catalog without touching files.
    """

    def match(self, command: str) -> tuple[CowrieCommandRule, ...]:
        """Return all reviewed rules matching a Cowrie command line."""
        ...


class EmptyCowrieCommandRuleCatalog:
    """No-op catalog used when command-level mapping is intentionally disabled."""

    def match(self, command: str) -> tuple[CowrieCommandRule, ...]:
        return ()


class CompositeCowrieCommandRuleCatalog:
    """Query several catalogs and return a deduplicated combined match list.

    The `hybrid` runtime mode uses this to keep project-specific mappings while
    also reading external Sigma rules directly.
    """

    def __init__(self, catalogs: Sequence[CowrieCommandRuleCatalog]) -> None:
        self._catalogs = tuple(catalogs)

    def match(self, command: str) -> tuple[CowrieCommandRule, ...]:
        rules: list[CowrieCommandRule] = []
        for catalog in self._catalogs:
            rules.extend(catalog.match(command))
        return tuple(
            dedupe_preserve_by(rules, lambda rule: (rule.name, rule.technique_id))
        )


class FileCowrieCommandRuleCatalog:
    """JSON-backed command mapping catalog.

    Rules are loaded lazily on the first match call. That keeps app startup
    cheap and makes tests simpler because the file is only read when needed.
    """

    def __init__(self, path: str | Path | Sequence[str | Path]) -> None:
        self._paths = _paths_from(path)
        self._loaded = False
        self._rules: tuple[CowrieCommandRule, ...] = ()

    def match(self, command: str) -> tuple[CowrieCommandRule, ...]:
        """Return every reviewed rule that matches one Cowrie command line.

        Example:
            match("nmap 10.0.0.0/24") returns the network_service_discovery
            rule if that rule exists in the JSON catalog.
        """
        self._ensure_loaded()
        normalized = normalize_command(command)
        if normalized is None:
            return ()
        return tuple(rule for rule in self._rules if command_matches_rule(normalized, rule))

    def _ensure_loaded(self) -> None:
        """Load and cache JSON rules exactly once."""
        if self._loaded:
            return

        rules: list[CowrieCommandRule] = []
        for path in self._paths:
            payload = json.loads(path.read_text(encoding="utf-8"))
            rules.extend(
                _rule_from_payload(item)
                for item in payload.get("rules", [])
                if isinstance(item, dict)
            )
        self._rules = tuple(
            dedupe_preserve_by(rules, lambda rule: (rule.name, rule.technique_id))
        )
        self._loaded = True


def normalize_command(command: str) -> NormalizedCommand | None:
    """Parse attacker input into a minimal process-like event.

    Example:
        "/usr/bin/wget http://x/payload.sh" becomes:
        process_name="wget"
        args=("http://x/payload.sh",)

    Returns None for empty input because there is no behavior to map.
    """
    command_line = command.strip()
    if not command_line:
        return None

    try:
        # shlex keeps quoted arguments together, e.g. grep "private key" file.
        parts = shlex.split(command_line)
    except ValueError:
        # Attackers often type broken quoting; keep mapping best-effort instead
        # of dropping useful intent from malformed command strings.
        parts = command_line.split()
    if not parts:
        return None

    process_name = Path(parts[0]).name.lower()
    args = tuple(part.lower() for part in parts[1:])
    return NormalizedCommand(
        command_line=command_line.lower(),
        process_name=process_name,
        args=args,
    )


def command_matches_rule(command: NormalizedCommand, rule: CowrieCommandRule) -> bool:
    """Return True when all specified rule conditions match the command.

    Matching semantics:
        process_names: command.process_name must be one listed value.
        command_line_contains_any: at least one substring must appear.
        command_line_regex_any: at least one regex must match.

    If a rule specifies multiple condition groups, every group must pass.
    A rule with no conditions is treated as invalid and never matches.
    """
    if not _command_matches(command, rule.match):
        return False
    if rule.exclude_match is not None and _command_matches(command, rule.exclude_match):
        return False
    return True


def _command_matches(command: NormalizedCommand, match: CommandMatch) -> bool:
    """Return True when all specified match condition groups pass."""
    has_condition = False

    if match.process_names:
        has_condition = True
        if command.process_name not in match.process_names:
            return False

    if match.command_line_contains_any:
        has_condition = True
        if not any(token in command.command_line for token in match.command_line_contains_any):
            return False

    if match.command_line_regex_any:
        has_condition = True
        if not any(re.search(pattern, command.command_line) for pattern in match.command_line_regex_any):
            return False

    return has_condition


def _rule_from_payload(payload: dict[str, object]) -> CowrieCommandRule:
    """Convert one JSON rule object into the immutable runtime dataclass."""
    return CowrieCommandRule(
        name=str(payload.get("name", "unnamed_command_rule")),
        technique_id=str(payload.get("technique_id", "")),
        confidence=str(payload.get("confidence", "medium")),
        match=_match_from_payload(payload.get("match", {})),
        source_refs=tuple(
            _source_ref_from_payload(item)
            for item in payload.get("source_refs", [])
            if isinstance(item, dict)
        ),
        exclude_match=_optional_match_from_payload(payload.get("exclude_match")),
    )


def _match_from_payload(payload: object) -> CommandMatch:
    """Convert the JSON match section into normalized lower-case conditions."""
    if not isinstance(payload, dict):
        payload = {}
    return CommandMatch(
        process_names=tuple(_lower_strings(payload.get("process_names", []))),
        command_line_contains_any=tuple(
            _lower_strings(payload.get("command_line_contains_any", []))
        ),
        command_line_regex_any=tuple(
            _strings(payload.get("command_line_regex_any", []))
        ),
    )


def _optional_match_from_payload(payload: object) -> CommandMatch | None:
    """Return an exclude match only when the JSON section is present."""
    if payload is None:
        return None
    return _match_from_payload(payload)


def _source_ref_from_payload(payload: dict[str, object]) -> SourceRef:
    """Convert one JSON source reference into a SourceRef."""
    url = payload.get("url")
    return SourceRef(
        type=str(payload.get("type", "")),
        name=str(payload.get("name", "")),
        url=str(url) if url is not None else None,
    )


def _paths_from(path: str | Path | Sequence[str | Path]) -> tuple[Path, ...]:
    """Normalize one mapping file or several mapping files into Path objects."""
    if isinstance(path, (str, Path)):
        return (Path(path),)
    return tuple(Path(item) for item in path)


def _lower_strings(value: object) -> list[str]:
    """Return a lower-case string list, or an empty list for invalid input."""
    if not isinstance(value, list):
        return []
    return [str(item).lower() for item in value]


def _strings(value: object) -> list[str]:
    """Return a string list without changing regex escape sequences."""
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]
