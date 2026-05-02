#!/usr/bin/env python3
"""Validate reviewed Cowrie command mappings against MITRE ATT&CK STIX.

This script keeps `data/cowrie/command_mapping_rules.json` honest: rule
patterns must be syntactically valid, source references must be present, and
every ATT&CK technique id must exist in the MITRE STIX bundle.

Example:
    .venv/bin/python scripts/validation/cowrie_attack_mappings.py

What this proves:
    The JSON rule schema is well-formed and technique ids are real ATT&CK ids.

What this does not prove:
    A rule is semantically perfect for every attacker command. That still needs
    human review, examples, and later comparison with real honeypot data.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

VALID_CONFIDENCE = {"high", "medium", "low"}


@dataclass(frozen=True)
class TechniqueMetadata:
    """Minimal ATT&CK technique metadata needed by the validator.

    Example:
        TechniqueMetadata(
            tech_id="T1083",
            name="File and Directory Discovery",
            tactic="Discovery",
        )
    """

    tech_id: str
    name: str
    tactic: str | None


def load_attack_techniques(stix_path: Path) -> dict[str, TechniqueMetadata]:
    """Load ATT&CK technique ids, names, and first tactic from STIX JSON.

    MITRE STIX stores techniques as `attack-pattern` objects. The human ATT&CK
    id, such as T1083, lives in `external_references[*].external_id`, while the
    tactic is stored indirectly through `kill_chain_phases`.
    """
    payload = json.loads(stix_path.read_text(encoding="utf-8"))
    objects = payload.get("objects", [])
    # Tactics are separate x-mitre-tactic objects, so load a shortname -> name
    # lookup first. Example: "discovery" -> "Discovery".
    tactic_names = _load_tactic_names(objects)

    techniques: dict[str, TechniqueMetadata] = {}
    for item in objects:
        # Only attack-pattern objects represent techniques/sub-techniques.
        if item.get("type") != "attack-pattern" or _is_retired(item):
            continue
        tech_id = _external_attack_id(item)
        if tech_id is None:
            continue

        phase_name = _first_attack_phase(item)
        tactic = tactic_names.get(_normalize_tactic_name(phase_name)) if phase_name else None
        techniques[tech_id] = TechniqueMetadata(
            tech_id=tech_id,
            name=str(item.get("name", "")),
            tactic=tactic,
        )
    return techniques


def validate_command_mapping_rules(
    mapping_path: Path,
    techniques: dict[str, TechniqueMetadata],
) -> list[str]:
    """Return validation errors for the Cowrie command mapping rules.

    Example error:
        "credential_file_search has unknown technique_id: T9999"

    Returning a list instead of raising immediately lets the user fix all rule
    problems in one pass instead of discovering them one at a time.
    """
    payload = json.loads(mapping_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    seen_names: set[str] = set()

    for index, rule in enumerate(payload.get("rules", []), start=1):
        if not isinstance(rule, dict):
            errors.append(f"rules[{index}] must be an object")
            continue

        # Rule names are used in profiler explanations, so they should be
        # stable, readable, and unique.
        name = str(rule.get("name", "")).strip()
        if not name:
            errors.append(f"rules[{index}] missing name")
        elif name in seen_names:
            errors.append(f"rules[{index}] duplicate name: {name}")
        seen_names.add(name)

        # This is the main MITRE validation step: the id must exist in the
        # downloaded enterprise-attack STIX bundle.
        tech_id = str(rule.get("technique_id", "")).strip()
        if tech_id not in techniques:
            errors.append(f"{name or f'rules[{index}]'} has unknown technique_id: {tech_id}")

        # Confidence is deliberately a small enum so profile scoring can remain
        # simple and explainable.
        confidence = str(rule.get("confidence", "")).strip().lower()
        if confidence not in VALID_CONFIDENCE:
            errors.append(f"{name or f'rules[{index}]'} has invalid confidence: {confidence}")

        # The match section is the part the runtime command mapper actually
        # executes, so typos here would silently break detection without this
        # validation.
        match = rule.get("match")
        if not isinstance(match, dict):
            errors.append(f"{name or f'rules[{index}]'} match must be an object")
        else:
            errors.extend(_validate_match(name or f"rules[{index}]", match))

        # Source references make each rule defensible in the thesis: we can say
        # whether it came from MITRE, Elastic, or another reviewed source.
        source_refs = rule.get("source_refs")
        if not isinstance(source_refs, list) or not source_refs:
            errors.append(f"{name or f'rules[{index}]'} must include source_refs")
        else:
            errors.extend(_validate_source_refs(name or f"rules[{index}]", source_refs))

    return errors


def summarize_rules(
    mapping_path: Path,
    techniques: dict[str, TechniqueMetadata],
) -> list[str]:
    """Return a human-readable mapping summary for successful validation.

    Example line:
        file_directory_discovery -> T1083 File and Directory Discovery
        (Discovery, confidence=medium)
    """
    payload = json.loads(mapping_path.read_text(encoding="utf-8"))
    lines: list[str] = []
    for rule in payload.get("rules", []):
        if not isinstance(rule, dict):
            continue
        tech_id = str(rule.get("technique_id", "")).strip()
        metadata = techniques.get(tech_id)
        if metadata is None:
            continue
        lines.append(
            f"{rule.get('name')} -> {tech_id} {metadata.name}"
            f" ({metadata.tactic or 'unknown tactic'}, confidence={rule.get('confidence')})"
        )
    return lines


def _validate_match(rule_name: str, match: dict[str, object]) -> list[str]:
    """Validate the supported runtime match fields for one rule.

    Supported fields mirror `CommandMatch` in services/cowrie/command_mapping.py:
        process_names
        command_line_contains_any
        command_line_regex_any

    Any unknown field is treated as an error because a typo like
    `process_name` would otherwise be ignored by the runtime mapper.
    """
    errors: list[str] = []
    known_fields = {
        "process_names",
        "command_line_contains_any",
        "command_line_regex_any",
    }
    unknown_fields = sorted(set(match) - known_fields)
    for field in unknown_fields:
        errors.append(f"{rule_name} has unsupported match field: {field}")

    has_condition = False
    for field in ("process_names", "command_line_contains_any"):
        values = match.get(field)
        if values is None:
            continue
        # These fields must be non-empty lists when present. Empty lists are
        # rejected because they make rule intent ambiguous.
        if not _is_non_empty_string_list(values):
            errors.append(f"{rule_name}.{field} must be a non-empty string list when present")
        else:
            has_condition = True

    regex_values = match.get("command_line_regex_any")
    if regex_values is None:
        regex_values = []
    elif not _is_non_empty_string_list(regex_values):
        errors.append(
            f"{rule_name}.command_line_regex_any must be a non-empty string list when present"
        )
    else:
        has_condition = True
        for pattern in regex_values:
            try:
                # Compile every regex now so the live Cowrie ingestion path does
                # not discover bad patterns only after an attacker types a match.
                re.compile(str(pattern))
            except re.error as exc:
                errors.append(f"{rule_name} has invalid regex {pattern!r}: {exc}")

    if not has_condition:
        # A rule with no conditions would either match everything or nothing,
        # depending on runtime interpretation. We reject it explicitly.
        errors.append(f"{rule_name} must include at least one match condition")
    return errors


def _validate_source_refs(rule_name: str, source_refs: list[object]) -> list[str]:
    """Validate source_refs for one rule.

    Example source_ref:
        {
          "type": "mitre_attack_technique",
          "name": "Network Service Discovery",
          "url": "https://attack.mitre.org/techniques/T1046/"
        }
    """
    errors: list[str] = []
    for index, source_ref in enumerate(source_refs, start=1):
        if not isinstance(source_ref, dict):
            errors.append(f"{rule_name}.source_refs[{index}] must be an object")
            continue
        if not str(source_ref.get("type", "")).strip():
            errors.append(f"{rule_name}.source_refs[{index}] missing type")
        if not str(source_ref.get("name", "")).strip():
            errors.append(f"{rule_name}.source_refs[{index}] missing name")
    return errors


def _is_non_empty_string_list(value: object) -> bool:
    """Return True for lists such as ["cat", "grep"], false otherwise."""
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and item for item in value
    )


def _load_tactic_names(objects: list[object]) -> dict[str, str]:
    """Build a normalized ATT&CK tactic lookup from STIX tactic objects.

    Example:
        x_mitre_shortname="credential-access" -> "Credential Access"
    """
    tactic_names: dict[str, str] = {}
    for item in objects:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "x-mitre-tactic" or _is_retired(item):
            continue
        shortname = item.get("x_mitre_shortname")
        name = item.get("name")
        if isinstance(shortname, str) and isinstance(name, str):
            tactic_names[_normalize_tactic_name(shortname)] = name
    return tactic_names


def _external_attack_id(item: dict[str, object]) -> str | None:
    """Extract the public ATT&CK id from a STIX attack-pattern object.

    Example:
        external_references=[{"external_id": "T1046"}] -> "T1046"
    """
    for reference in item.get("external_references", []) or []:
        if not isinstance(reference, dict):
            continue
        external_id = reference.get("external_id")
        if isinstance(external_id, str) and external_id.startswith("T"):
            return external_id
    return None


def _first_attack_phase(item: dict[str, object]) -> str | None:
    """Return the first MITRE kill-chain phase for a technique.

    Example:
        kill_chain_phases=[{"kill_chain_name": "mitre-attack",
                            "phase_name": "discovery"}]
        -> "discovery"
    """
    for phase in item.get("kill_chain_phases", []) or []:
        if not isinstance(phase, dict):
            continue
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name"):
            return str(phase["phase_name"])
    return None


def _is_retired(item: dict[str, object]) -> bool:
    """Return True for revoked or deprecated ATT&CK objects."""
    return bool(item.get("revoked")) or bool(item.get("x_mitre_deprecated"))


def _normalize_tactic_name(tactic: str | None) -> str:
    """Normalize tactic spellings so STIX shortnames can be matched reliably.

    Example:
        "credential-access" -> "credential access"
        "Credential_Access" -> "credential access"
    """
    if tactic is None:
        return ""
    return " ".join(
        tactic.replace("-", " ").replace("_", " ").strip().lower().split()
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI paths, keeping repo defaults convenient for local validation."""
    parser = argparse.ArgumentParser(
        description="Validate Cowrie command mapping rules against ATT&CK STIX.",
    )
    parser.add_argument(
        "--mapping-file",
        type=Path,
        default=Path("data/cowrie/command_mapping_rules.json"),
        help="Path to Cowrie command mapping rules.",
    )
    parser.add_argument(
        "--stix-file",
        type=Path,
        default=Path("data/mitre/enterprise-attack.json"),
        help="Path to MITRE ATT&CK Enterprise STIX JSON.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: validate rules, print errors or a success summary."""
    args = parse_args(argv)
    techniques = load_attack_techniques(args.stix_file)
    errors = validate_command_mapping_rules(args.mapping_file, techniques)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    for line in summarize_rules(args.mapping_file, techniques):
        print(line)
    print("Cowrie command mapping validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
