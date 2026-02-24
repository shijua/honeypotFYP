from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from libs.contracts.models import BindingRecord


class BindingRepository(Protocol):
    # Port interface: production adapters (DB/Redis) and test doubles share this contract.
    def get_by_attacker(self, attacker_key: str) -> BindingRecord | None:
        """Return the current binding for attacker_key, if any."""
        ...

    def get_by_binding(self, binding_id: str) -> BindingRecord | None:
        """Return one binding by logical binding_id."""
        ...

    def upsert(self, record: BindingRecord) -> BindingRecord:
        """Insert or update one binding record."""
        ...

    def list_all(self) -> Iterable[BindingRecord]:
        """List all records (mainly for diagnostics/tests)."""
        ...


class InMemoryBindingRepository:
    """In-memory repository used by local runs and tests.

    This implementation keeps two indexes:
    - binding_id -> BindingRecord
    - attacker_key -> binding_id
    """

    def __init__(self) -> None:
        # Primary index by logical binding id.
        self._by_binding: dict[str, BindingRecord] = {}
        # Secondary index for sticky attacker_key -> binding lookup.
        self._by_attacker: dict[str, str] = {}

    def get_by_attacker(self, attacker_key: str) -> BindingRecord | None:
        binding_id = self._by_attacker.get(attacker_key)
        if binding_id is None:
            return None
        return self._by_binding.get(binding_id)

    def get_by_binding(self, binding_id: str) -> BindingRecord | None:
        return self._by_binding.get(binding_id)

    def upsert(self, record: BindingRecord) -> BindingRecord:
        # Upsert keeps both indexes in sync and enables idempotent writes in tests.
        self._by_binding[record.binding_id] = record
        self._by_attacker[record.attacker_key] = record.binding_id
        return record

    def list_all(self) -> Iterable[BindingRecord]:
        return tuple(self._by_binding.values())
