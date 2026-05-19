"""Shared helpers for Cowrie local and Sigma command mapping."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SourceRef:
    """External reference used to justify a command mapping rule.

    Example:
        SourceRef(type="sigma", name="Linux Suspicious Download", url="https://...")
    """

    type: str
    name: str
    url: str | None = None


def source_ref_from_payload(payload: dict[str, object]) -> SourceRef:
    """Convert one JSON-style source reference into a SourceRef.

    Example:
        {"type": "sigma", "name": "curl download"} -> SourceRef(type="sigma", name="curl download")
    """
    url = payload.get("url")
    return SourceRef(
        type=str(payload.get("type", "")),
        name=str(payload.get("name", "")),
        url=str(url) if url is not None else None,
    )


def paths_from(path: str | Path | Sequence[str | Path]) -> tuple[Path, ...]:
    """Normalize one mapping path or many mapping paths into Path objects.

    Example:
        paths_from(["a.json", Path("b.json")]) -> (Path("a.json"), Path("b.json"))
    """
    if isinstance(path, (str, Path)):
        return (Path(path),)
    return tuple(Path(item) for item in path)


def lower_strings(value: object) -> list[str]:
    """Return a lower-case string list, or an empty list for invalid input."""
    if not isinstance(value, list):
        return []
    return [str(item).lower() for item in value]


def strings(value: object) -> list[str]:
    """Return a string list without changing regex escape sequences."""
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]
