"""Small ATT&CK technique helpers shared by controller and evaluation code."""

from __future__ import annotations

from collections.abc import Iterable
import re

ATTACK_TECHNIQUE_RE = re.compile(r"(?i)\b(?:attack[._-])?(T\d{4})(?:[./](\d{3}))?\b")


def attack_technique_ids_from_text(text: str) -> list[str]:
    """Return ATT&CK technique ids found in free text.

    Example:
        attack_technique_ids_from_text("attack.t1552.001 then T1105") -> ["T1552.001", "T1105"]
    """
    techniques: list[str] = []
    for match in ATTACK_TECHNIQUE_RE.finditer(text):
        base = match.group(1).upper()
        sub = match.group(2)
        techniques.append(f"{base}.{sub}" if sub else base)
    return techniques


def technique_family(technique: str) -> str:
    """Return the parent technique family for parent/sub-technique matching."""
    return technique.split(".", 1)[0]


def same_technique_family(left: str, right: str) -> bool:
    """Return whether two ATT&CK ids share the same parent technique."""
    return technique_family(left) == technique_family(right)


def technique_family_set(techniques: Iterable[object]) -> set[str]:
    """Return parent technique families from an iterable of mixed values."""
    return {
        technique_family(item)
        for item in techniques
        if isinstance(item, str) and item
    }
