from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from libs.common.json_store import JsonFileStore
from libs.contracts.models import GatewayBindingState


class GatewayRouteRepository(Protocol):
    def get(self, binding_id: str) -> GatewayBindingState | None:
        """Return one gateway state by binding_id."""
        ...

    def get_by_attacker(self, attacker_key: str) -> GatewayBindingState | None:
        """Return one gateway state by attacker_key."""
        ...

    def upsert(self, state: GatewayBindingState) -> GatewayBindingState:
        """Insert or update one gateway route state."""
        ...

    def list_all(self) -> Iterable[GatewayBindingState]:
        """List known gateway states."""
        ...


class InMemoryGatewayRouteRepository:
    """In-memory gateway state used by tests and local isolated runs."""

    def __init__(self) -> None:
        self._by_binding: dict[str, GatewayBindingState] = {}

    def get(self, binding_id: str) -> GatewayBindingState | None:
        return self._by_binding.get(binding_id)

    def get_by_attacker(self, attacker_key: str) -> GatewayBindingState | None:
        for state in self._by_binding.values():
            if state.attacker_key == attacker_key:
                return state
        return None

    def upsert(self, state: GatewayBindingState) -> GatewayBindingState:
        self._by_binding[state.binding_id] = state
        return state

    def list_all(self) -> Iterable[GatewayBindingState]:
        return tuple(self._by_binding.values())


class FileGatewayRouteRepository:
    """File-backed gateway state used by the default local runtime."""

    def __init__(self, path: str | Path) -> None:
        self._store = JsonFileStore(path, default_data={"routes": []})

    def get(self, binding_id: str) -> GatewayBindingState | None:
        return self._states_by_binding().get(binding_id)

    def get_by_attacker(self, attacker_key: str) -> GatewayBindingState | None:
        for state in self._states_by_binding().values():
            if state.attacker_key == attacker_key:
                return state
        return None

    def upsert(self, state: GatewayBindingState) -> GatewayBindingState:
        states = self._states_by_binding()
        states[state.binding_id] = state
        payload = {
            "routes": [item.model_dump(mode="json") for item in states.values()],
        }
        self._store.write(payload)
        return state

    def list_all(self) -> Iterable[GatewayBindingState]:
        return tuple(self._states_by_binding().values())

    def _states_by_binding(self) -> dict[str, GatewayBindingState]:
        payload = self._store.read()
        return {
            item["binding_id"]: GatewayBindingState.model_validate(item)
            for item in payload.get("routes", [])
        }
