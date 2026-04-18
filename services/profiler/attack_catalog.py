from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Protocol


class AttackCatalog(Protocol):
    def tactic_for_technique(self, tech_id: str) -> str | None:
        """Return the canonical tactic name for one ATT&CK technique id."""
        ...

    def default_technique_for_tactic(self, tactic: str) -> str | None:
        """Return one deterministic technique id for a tactic."""
        ...

    def canonical_tactic_name(self, tactic: str) -> str | None:
        """Return the canonical ATT&CK tactic display name."""
        ...


class MitreAttackCatalog:
    """Load ATT&CK tactic/technique relationships from MITRE STIX data."""

    def __init__(self, stix_path: str | Path) -> None:
        self._stix_path = Path(stix_path)
        self._loaded = False
        self._technique_to_tactic: dict[str, str] = {}
        self._tactic_to_techniques: dict[str, list[str]] = {}
        self._tactic_names: dict[str, str] = {}

    def tactic_for_technique(self, tech_id: str) -> str | None:
        self._ensure_loaded()
        return self._technique_to_tactic.get(tech_id)

    def default_technique_for_tactic(self, tactic: str) -> str | None:
        self._ensure_loaded()
        normalized = _normalize_tactic_name(tactic)
        techniques = self._tactic_to_techniques.get(normalized)
        if not techniques:
            return None
        return sorted(techniques)[0]

    def canonical_tactic_name(self, tactic: str) -> str | None:
        self._ensure_loaded()
        return self._tactic_names.get(_normalize_tactic_name(tactic))

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return

        payload = json.loads(self._stix_path.read_text(encoding="utf-8"))
        objects = payload.get("objects", [])

        tactic_names: dict[str, str] = {}
        for item in objects:
            if item.get("type") != "x-mitre-tactic" or _is_retired(item):
                continue
            shortname = item.get("x_mitre_shortname")
            name = item.get("name")
            if shortname and name:
                tactic_names[_normalize_tactic_name(shortname)] = name

        tactic_to_techniques: dict[str, list[str]] = defaultdict(list)
        technique_to_tactic: dict[str, str] = {}
        for item in objects:
            if item.get("type") != "attack-pattern" or _is_retired(item):
                continue
            tech_id = _external_attack_id(item)
            if tech_id is None:
                continue

            phase_names = [
                phase.get("phase_name")
                for phase in item.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
            ]
            if not phase_names:
                continue

            # The profile model stores one tactic per evidence, so use the first phase.
            normalized_tactic = _normalize_tactic_name(phase_names[0])
            tactic_name = tactic_names.get(
                normalized_tactic,
                _display_tactic_name(phase_names[0]),
            )
            tactic_names.setdefault(normalized_tactic, tactic_name)
            technique_to_tactic[tech_id] = tactic_name
            tactic_to_techniques[normalized_tactic].append(tech_id)

        self._tactic_names = tactic_names
        self._technique_to_tactic = technique_to_tactic
        self._tactic_to_techniques = tactic_to_techniques
        self._loaded = True


def _external_attack_id(item: dict[str, object]) -> str | None:
    for reference in item.get("external_references", []) or []:
        if not isinstance(reference, dict):
            continue
        external_id = reference.get("external_id")
        if isinstance(external_id, str) and external_id.startswith("T"):
            return external_id
    return None


def _is_retired(item: dict[str, object]) -> bool:
    return bool(item.get("revoked")) or bool(item.get("x_mitre_deprecated"))


def _normalize_tactic_name(tactic: str) -> str:
    return " ".join(
        tactic.replace("-", " ").replace("_", " ").strip().lower().split()
    )


def _display_tactic_name(phase_name: str) -> str:
    words = _normalize_tactic_name(phase_name).split()
    if not words:
        return phase_name
    return " ".join(
        word if word in {"and"} else word.capitalize()
        for word in words
    )
