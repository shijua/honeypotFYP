"""Small iterable helpers shared across services and scripts."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TypeVar

T = TypeVar("T")
K = TypeVar("K")


def dedupe_preserve(values: Iterable[T]) -> list[T]:
    """Return unique values while preserving first-seen order."""
    ordered: list[T] = []
    for value in values:
        if value not in ordered:
            ordered.append(value)
    return ordered


def dedupe_preserve_by(values: Iterable[T], key: Callable[[T], K]) -> list[T]:
    """Return unique values by derived key while preserving first-seen order."""
    seen: set[K] = set()
    ordered: list[T] = []
    for value in values:
        marker = key(value)
        if marker in seen:
            continue
        seen.add(marker)
        ordered.append(value)
    return ordered


def string_items(value: object) -> list[str]:
    """Return string items from a JSON-style list, otherwise an empty list.

    Example:
        string_items(["e-1", 2, "e-2"]) -> ["e-1", "e-2"]
    """
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]
