from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol


class RouteStateRepository(Protocol):
    def append_route_update(self, binding_id: str, route_update: str) -> None:
        """Record one route/configuration update for a binding."""
        ...

    def list_route_updates(self, binding_id: str) -> Iterable[str]:
        """Return recorded route updates for a binding."""
        ...


class InMemoryRouteStateRepository:
    """In-memory route/action journal for local runs and tests."""

    def __init__(self) -> None:
        # Keep mock route updates by binding_id.
        self._updates: dict[str, list[str]] = {}

    def append_route_update(self, binding_id: str, route_update: str) -> None:
        bucket = self._updates.setdefault(binding_id, [])
        bucket.append(route_update)

    def list_route_updates(self, binding_id: str) -> Iterable[str]:
        return tuple(self._updates.get(binding_id, ()))
