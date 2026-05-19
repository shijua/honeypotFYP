"""JSON file helpers for scripts and dashboard summaries."""

from __future__ import annotations

from copy import deepcopy
import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Iterable


def read_json_value(path: Path, default: Any) -> Any:
    """Read JSON from disk, returning a copy of default when unavailable."""
    if not path.exists():
        return deepcopy(default)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, JSONDecodeError):
        return deepcopy(default)


def read_json_object(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    """Read a JSON object from disk, returning a copy of default if absent."""
    payload = read_json_value(path, default)
    return payload if isinstance(payload, dict) else deepcopy(default)


def first_value(payload: dict[str, object], *keys: str) -> object | None:
    """Return the first present value from a JSON-style object.

    Example:
        first_value({"src_ip": "198.51.100.10"}, "attacker_key", "src_ip") -> "198.51.100.10"
    """
    for key in keys:
        value = payload.get(key)
        if value is not None:
            return value
    return None


def string_or_none(value: object | None) -> str | None:
    """Return a non-empty string value, otherwise None.

    Example:
        string_or_none("asset-1") -> "asset-1"
        string_or_none("  asset-1  ") -> "asset-1"
        string_or_none("") -> None
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def first_string(payload: dict[str, object], *keys: str) -> str | None:
    """Return the first present non-empty string from a JSON-style object.

    Example:
        first_string({"remote_ip": "198.51.100.10"}, "src_ip", "remote_ip") -> "198.51.100.10"
    """
    return string_or_none(first_value(payload, *keys))


def mutable_nested_dict(payload: dict[str, Any], keys: Iterable[str]) -> dict[str, Any]:
    """Return a writable nested dict, creating or repairing each level.

    Example:
        payload = {}
        mutable_nested_dict(payload, ("contexts", "T1005", "asset_groups", "finance"))
        # payload now has payload["contexts"]["T1005"]["asset_groups"]["finance"] == {}
    """
    current = payload
    for key in keys:
        value = current.setdefault(key, {})
        if not isinstance(value, dict):
            value = {}
            current[key] = value
        current = value
    return current
