"""Small JSON persistence helper for file-backed adapters.

Repositories use this helper to load/write JSON atomically without duplicating
file handling code in every adapter.
"""

from __future__ import annotations

import json
import tempfile
from copy import deepcopy
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, TypeVar

import fcntl

from libs.common.json_utils import mutable_nested_dict


UpdateResultT = TypeVar("UpdateResultT")


class JsonFileStore:
    """Small JSON helper for MVP file-backed repositories.

    Example:
        store = JsonFileStore("data/runtime/profiles.json", {"profiles": {}})
    """

    def __init__(self, path: str | Path, default_data: Any) -> None:
        self._path = Path(path)
        self._default_data = default_data
        self._ensure_exists()

    def read(self) -> Any:
        """Read the current JSON payload, creating the default file if missing.

        Example:
            JsonFileStore("bindings.json", {"records": []}).read() -> {"records": []}
        """
        self._ensure_exists()
        with self._path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def write(self, data: Any) -> None:
        """Atomically replace the JSON file with a readable payload.

        Example:
            write({"records": []}) creates a temporary file, chmods it 0644, then renames it over the target so readers never see partial JSON.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock_file() as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                self._write_unlocked(data)
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def update(self, mutator: Callable[[Any], UpdateResultT]) -> UpdateResultT:
        """Run one read-modify-write cycle under an exclusive file lock.

        Multiple runtime services append evidence and observations at the same
        time. This helper keeps those file-backed updates from overwriting each
        other while still storing a normal JSON document on disk.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock_file() as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                payload = self._read_unlocked()
                result = mutator(payload)
                self._write_unlocked(payload)
                return result
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def append_to_list(self, list_key: str, item: Any) -> None:
        """Append one item to a top-level JSON list under a file lock."""
        with self._locked_payload() as payload:
            items = payload.get(list_key)
            if not isinstance(items, list):
                items = []
                payload[list_key] = items
            items.append(item)

    def extend_list_in_object(
        self,
        object_key: str,
        bucket_key: str,
        items: Iterable[Any],
    ) -> None:
        """Extend `payload[object_key][bucket_key]` as a list under a file lock."""
        with self._locked_payload() as payload:
            bucket_parent = payload.get(object_key)
            if not isinstance(bucket_parent, dict):
                bucket_parent = {}
                payload[object_key] = bucket_parent
            bucket = bucket_parent.get(bucket_key)
            if not isinstance(bucket, list):
                bucket = []
                bucket_parent[bucket_key] = bucket
            bucket.extend(items)

    def set_object_item(self, object_key: str, item_key: str, item: Any) -> None:
        """Set one key inside a top-level JSON object under a file lock."""
        with self._locked_payload() as payload:
            items = payload.get(object_key)
            if not isinstance(items, dict):
                items = {}
                payload[object_key] = items
            items[item_key] = item

    def upsert_list_item(
        self,
        list_key: str,
        match_key: str,
        match_value: object,
        item: dict[str, Any],
    ) -> None:
        """Replace or append one dict in a top-level list by a stable key."""
        with self._locked_payload() as payload:
            items = payload.get(list_key)
            if not isinstance(items, list):
                items = []
            replaced = False
            output: list[object] = []
            for existing in items:
                if (
                    isinstance(existing, dict)
                    and existing.get(match_key) == match_value
                ):
                    output.append(item)
                    replaced = True
                else:
                    output.append(existing)
            if not replaced:
                output.append(item)
            payload[list_key] = output

    def replace_list_items(
        self,
        list_key: str,
        new_items: Iterable[dict[str, Any]],
        key_fields: Iterable[str],
    ) -> None:
        """Replace dicts in a top-level list using a compound key."""
        fields = tuple(key_fields)
        replacements = list(new_items)
        replacement_keys = {_compound_key(item, fields) for item in replacements}
        with self._locked_payload() as payload:
            existing_items = payload.get(list_key)
            existing_items = existing_items if isinstance(existing_items, list) else []
            preserved = [
                item
                for item in existing_items
                if not isinstance(item, dict)
                or _compound_key(item, fields) not in replacement_keys
            ]
            payload[list_key] = [*preserved, *replacements]

    def increment_nested_int(self, keys: Iterable[str], counter_key: str) -> None:
        """Increment one integer in a nested JSON object under a file lock."""
        with self._locked_payload() as payload:
            group = mutable_nested_dict(payload, keys)
            group[counter_key] = int(group.get(counter_key, 0) or 0) + 1

    def _locked_payload(self) -> "_LockedPayload":
        return _LockedPayload(self)

    def _read_unlocked(self) -> Any:
        if not self._path.exists():
            return deepcopy(self._default_data)
        with self._path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _write_unlocked(self, data: Any) -> None:
        fd, raw_temp_path = tempfile.mkstemp(
            dir=self._path.parent,
            prefix=f".{self._path.name}.",
            suffix=".tmp",
            text=True,
        )
        temp_path = Path(raw_temp_path)
        try:
            with open(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
            temp_path.chmod(0o644)
            temp_path.replace(self._path)
        finally:
            temp_path.unlink(missing_ok=True)

    def _lock_file(self):
        lock_path = self._path.with_name(f".{self._path.name}.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        return lock_path.open("a+", encoding="utf-8")

    def _ensure_exists(self) -> None:
        """Create a missing JSON file with its repository default shape."""
        if self._path.exists():
            return
        self.write(deepcopy(self._default_data))


class _LockedPayload:
    def __init__(self, store: JsonFileStore) -> None:
        self._store = store
        self._lock_handle = None
        self.payload: Any = None

    def __enter__(self) -> Any:
        self._store._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_handle = self._store._lock_file()
        fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_EX)
        self.payload = self._store._read_unlocked()
        return self.payload

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._lock_handle is None:
            return
        try:
            if exc_type is None:
                self._store._write_unlocked(self.payload)
        finally:
            fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
            self._lock_handle.close()


def _compound_key(item: dict[str, Any], fields: tuple[str, ...]) -> tuple[object, ...]:
    return tuple(item.get(field) for field in fields)
