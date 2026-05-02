"""Repository interfaces and file-backed adapters for binding records."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from libs.common.json_store import JsonFileStore
from libs.contracts.models import BindingRecord


class BindingRepository(Protocol):
    """Storage contract for binding records.

    Example:
        get_by_attacker("198.51.100.10") -> BindingRecord | None
    """

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


class FileBindingRepository:
    """File-backed repository used by the default local runtime.

    Example file shape:
        {"records": [{...BindingRecord...}]}
    """

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
