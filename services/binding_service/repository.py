from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from libs.common.json_store import JsonFileStore
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


class FileBindingRepository:
    """File-backed repository used by the default local runtime."""

    def __init__(self, path: str | Path) -> None:
        self._store = JsonFileStore(path, default_data={"records": []})

    def get_by_attacker(self, attacker_key: str) -> BindingRecord | None:
        return self._records_by_attacker().get(attacker_key)

    def get_by_binding(self, binding_id: str) -> BindingRecord | None:
        return self._records_by_binding().get(binding_id)

    def upsert(self, record: BindingRecord) -> BindingRecord:
        records = self._records_by_binding()
        records[record.binding_id] = record
        payload = {
            "records": [item.model_dump(mode="json") for item in records.values()],
        }
        self._store.write(payload)
        return record

    def list_all(self) -> Iterable[BindingRecord]:
        return tuple(self._records_by_binding().values())

    def _records_by_binding(self) -> dict[str, BindingRecord]:
        payload = self._store.read()
        return {
            item["binding_id"]: BindingRecord.model_validate(item)
            for item in payload.get("records", [])
        }

    def _records_by_attacker(self) -> dict[str, BindingRecord]:
        return {
            record.attacker_key: record
            for record in self._records_by_binding().values()
        }
