"""Helpers for reading common runtime JSON record files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from libs.common.json_utils import read_json_object


def list_records(path: Path, key: str) -> list[dict[str, Any]]:
    """Read a list of JSON object records from a runtime JSON file.

    Missing files, malformed files, non-object payloads, and non-list values all
    return an empty list. Non-object items inside the list are skipped because
    runtime consumers expect dict-like records.

    Example:
        File:
            {"records": [{"binding_id": "b1"}, "bad"]}

        Call:
            list_records(Path("bindings.json"), "records")

        Output:
            [{"binding_id": "b1"}]
    """
    payload = read_json_object(path, {key: []})
    records = payload.get(key, [])
    if not isinstance(records, list):
        return []
    return [item for item in records if isinstance(item, dict)]


def evidence_records(path: Path, *, include_bucket_attacker: bool = False) -> list[dict[str, Any]]:
    """Flatten profiler evidence buckets from `data/runtime/evidence.json`.

    The evidence store is keyed by attacker. Dashboard views often need the
    attacker key copied into each record, while feedback matching only needs the
    stored evidence body. Use `include_bucket_attacker=True` for dashboard-style
    summaries.

    Example:
        File:
            {"records": {"198.51.100.1": [{"tech_id": "T1005"}]}}

        Call:
            evidence_records(path, include_bucket_attacker=True)

        Output:
            [{"tech_id": "T1005", "attacker_key": "198.51.100.1"}]
    """
    payload = read_json_object(path, {"records": {}})
    records = payload.get("records", {})
    if not isinstance(records, dict):
        return []
    flattened: list[dict[str, Any]] = []
    for attacker_key, bucket in records.items():
        if not isinstance(bucket, list):
            continue
        for item in bucket:
            if not isinstance(item, dict):
                continue
            record = dict(item)
            if include_bucket_attacker:
                record.setdefault("attacker_key", str(attacker_key))
            flattened.append(record)
    return flattened
