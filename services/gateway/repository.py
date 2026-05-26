"""Repository interfaces and file-backed adapters for gateway route state."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from libs.common.json_store import JsonFileStore
from libs.contracts.models import GatewayBindingState


class GatewayRouteRepository(Protocol):
    """Storage contract for gateway route state.

    Example:
        get("binding-1") -> GatewayBindingState | None
    """

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


class FileGatewayRouteRepository:
    """File-backed gateway state used by the default local runtime.

    Example file shape:
        {"routes": [{...GatewayBindingState...}]}
    """

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
        self._store.upsert_list_item(
            "routes",
            "binding_id",
            state.binding_id,
            state.model_dump(mode="json"),
        )
        return state

    def list_all(self) -> Iterable[GatewayBindingState]:
        return tuple(self._states_by_binding().values())

    def _states_by_binding(self) -> dict[str, GatewayBindingState]:
        payload = self._store.read()
        return {
            item["binding_id"]: GatewayBindingState.model_validate(item)
            for item in payload.get("routes", [])
        }
