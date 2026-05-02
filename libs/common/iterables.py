"""Small iterable helpers shared across services and scripts."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeVar

T = TypeVar("T")


def dedupe_preserve(values: Iterable[T]) -> list[T]:
    """Return unique values while preserving first-seen order."""
    ordered: list[T] = []
    for value in values:
        if value not in ordered:
            ordered.append(value)
    return ordered
