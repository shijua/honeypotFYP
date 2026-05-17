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
