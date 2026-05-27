#!/usr/bin/env python3
"""Validate the active ATT&CK group prior against local public datasets.

This is an offline check only. It scans local dataset files for ordered
ATT&CK-labelled technique traces, then asks the active group prior to recommend
future techniques from each prefix. It does not train a prior, start Docker, or
affect runtime controller behavior.

Example:
    python scripts/evaluation/public_dataset_prior_validation.py vendor/datasets
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path
from typing import Any
from zipfile import BadZipFile, ZipFile

import yaml

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from libs.common.attack import attack_technique_ids_from_text
from libs.common.config import RuntimeConfig
from libs.common.iterables import dedupe_preserve
from scripts.evaluation.attack_group_prior_recommendation import evaluate_trace_recommendations
from scripts.evaluation.charts import write_prior_recommendation_chart


SUPPORTED_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson", ".yaml", ".yml"}
TIME_FIELDS = ("timestamp", "time", "ts", "@timestamp", "event_time", "datetime", "date")
TECHNIQUE_FIELD_HINTS = ("technique", "technique_id", "attack_technique", "mitre", "attack_id", "label")
DEFAULT_MAX_FILE_BYTES = 2_000_000


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the active ATT&CK group prior on local public datasets.")
    parser.add_argument("dataset_paths", nargs="*", type=Path, default=[Path("vendor/datasets")])
    parser.add_argument("--prior", type=Path, default=Path("data/technique_prior/attack_group_technique_prior.json"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-files", type=int, default=2000)
    parser.add_argument("--max-zip-members", type=int, default=200)
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help="Skip individual files or zip members larger than this many bytes.",
    )
    args = parser.parse_args()

    report = evaluate_public_dataset_prior(
        dataset_paths=args.dataset_paths,
        prior_path=args.prior,
        max_files=args.max_files,
        max_zip_members=args.max_zip_members,
        max_file_bytes=args.max_file_bytes,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{text}\n", encoding="utf-8")
        write_prior_recommendation_chart(report, args.output.with_suffix(".svg"))
    else:
        print(text)
    return 0 if report["ok"] else 1


def evaluate_public_dataset_prior(
    *,
    dataset_paths: list[Path],
    prior_path: Path,
    max_files: int = 2000,
    max_zip_members: int = 200,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    config: RuntimeConfig | None = None,
) -> dict[str, Any]:
    """Extract local dataset traces and evaluate prior recommendations."""
    extraction = extract_dataset_traces(
        dataset_paths,
        max_files=max_files,
        max_zip_members=max_zip_members,
        max_file_bytes=max_file_bytes,
    )
    trace_report = evaluate_trace_recommendations(
        traces=extraction["traces"],
        prior_path=prior_path,
        config=config,
    )
    metrics = trace_report["metrics"]
    return {
        "schema_version": "v1",
        "ok": bool(extraction["traces"]) and metrics["prefix_count"] > 0 and metrics["degraded_reason"] is None,
        "dataset_paths": [str(path) for path in dataset_paths],
        "prior": str(prior_path),
        "top_k": trace_report["top_k"],
        "support_threshold": trace_report["support_threshold"],
        "evaluation_match": trace_report["evaluation_match"],
        "technique_family_universe_size": trace_report["technique_family_universe_size"],
        "trace_count": len(extraction["traces"]),
        "file_count": extraction["file_count"],
        "skipped_file_count": extraction["skipped_file_count"],
        "skipped_files": extraction["skipped_files"],
        "traces": [
            {
                "source_id": trace["scenario_id"],
                "technique_count": len(trace["techniques"]),
                "techniques": trace["techniques"],
            }
            for trace in extraction["traces"]
        ],
        "metrics": metrics,
    }


def extract_dataset_traces(
    dataset_paths: list[Path],
    *,
    max_files: int = 2000,
    max_zip_members: int = 200,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> dict[str, Any]:
    """Return ordered technique traces discovered under local dataset paths.

    Public datasets often include very large raw log files. This extractor is
    meant for lightweight offline validation, so it skips oversized files and
    records the reason instead of loading them into memory.
    """
    traces: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    file_count = 0
    for file_path in _iter_dataset_files(dataset_paths, max_files=max_files):
        file_count += 1
        if file_path.suffix.lower() == ".zip":
            extracted, zip_skipped = _traces_from_zip(
                file_path,
                max_members=max_zip_members,
                max_file_bytes=max_file_bytes,
            )
            traces.extend(extracted)
            skipped.extend(zip_skipped)
            continue
        size = _file_size(file_path)
        if size is None:
            skipped.append({"path": str(file_path), "reason": "file is not readable"})
            continue
        if size > max_file_bytes:
            skipped.append({"path": str(file_path), "reason": _too_large_reason(size, max_file_bytes)})
            continue
        trace = _trace_from_file(file_path)
        if trace is None:
            skipped.append({"path": str(file_path), "reason": "no ordered ATT&CK technique trace"})
        else:
            traces.append(trace)
    return {
        "traces": traces,
        "file_count": file_count,
        "skipped_file_count": len(skipped),
        "skipped_files": skipped[:200],
    }


def _iter_dataset_files(paths: list[Path], *, max_files: int) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            candidates = sorted(item for item in path.rglob("*") if item.is_file())
        else:
            continue
        for item in candidates:
            suffix = item.suffix.lower()
            if suffix == ".zip" or suffix in SUPPORTED_SUFFIXES:
                files.append(item)
            if len(files) >= max_files:
                return files
    return files


def _file_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _too_large_reason(size: int, max_file_bytes: int) -> str:
    return f"file too large: {size} > {max_file_bytes} bytes"


def _traces_from_zip(
    path: Path,
    *,
    max_members: int,
    max_file_bytes: int,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    traces: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    try:
        with ZipFile(path) as archive:
            members = [
                info
                for info in archive.infolist()
                if not info.is_dir() and Path(info.filename).suffix.lower() in SUPPORTED_SUFFIXES
            ][:max_members]
            for member in members:
                member_path = f"{path}!{member.filename}"
                if member.file_size > max_file_bytes:
                    skipped.append({"path": member_path, "reason": _too_large_reason(member.file_size, max_file_bytes)})
                    continue
                try:
                    text = archive.read(member).decode("utf-8", errors="replace")
                except (KeyError, OSError) as exc:
                    skipped.append({"path": member_path, "reason": str(exc)})
                    continue
                trace = _trace_from_text(text, source_id=member_path, suffix=Path(member.filename).suffix.lower())
                if trace is None:
                    skipped.append({"path": member_path, "reason": "no ordered ATT&CK technique trace"})
                else:
                    traces.append(trace)
    except BadZipFile as exc:
        skipped.append({"path": str(path), "reason": f"bad zip: {exc}"})
    return traces, skipped


def _trace_from_file(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return _trace_from_text(text, source_id=str(path), suffix=path.suffix.lower())


def _trace_from_text(text: str, *, source_id: str, suffix: str) -> dict[str, Any] | None:
    techniques: list[str]
    if suffix == ".csv":
        techniques = _techniques_from_csv(text)
    elif suffix in {".json", ".jsonl", ".ndjson"}:
        techniques = _techniques_from_jsonish(text, json_lines=suffix in {".jsonl", ".ndjson"})
    elif suffix in {".yaml", ".yml"}:
        techniques = _techniques_from_yaml(text)
    else:
        techniques = _techniques_from_text_blob(text)
    techniques = dedupe_preserve(techniques)
    if len(techniques) < 2:
        return None
    return {"scenario_id": source_id, "techniques": techniques}


def _techniques_from_csv(text: str) -> list[str]:
    sample = io.StringIO(text)
    try:
        rows = list(csv.DictReader(sample))
    except csv.Error:
        return _techniques_from_text_blob(text)
    if not rows:
        return _techniques_from_text_blob(text)
    rows = _sort_records_by_time(rows)
    techniques: list[str] = []
    for row in rows:
        techniques.extend(_techniques_from_mapping(row))
    return techniques or _techniques_from_text_blob(text)


def _techniques_from_jsonish(text: str, *, json_lines: bool) -> list[str]:
    objects: list[Any] = []
    if json_lines:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objects.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    else:
        try:
            objects = [json.loads(text)]
        except json.JSONDecodeError:
            return _techniques_from_text_blob(text)
    records = _records_from_objects(objects)
    if records:
        return [
            technique
            for record in _sort_records_by_time(records)
            for technique in _techniques_from_mapping(record)
        ]
    return _techniques_from_text_blob(text)


def _techniques_from_yaml(text: str) -> list[str]:
    try:
        payload = yaml.safe_load(text)
    except yaml.YAMLError:
        return _techniques_from_text_blob(text)
    records = _records_from_objects([payload])
    if records:
        return [
            technique
            for record in _sort_records_by_time(records)
            for technique in _techniques_from_mapping(record)
        ]
    return _techniques_from_text_blob(text)


def _records_from_objects(objects: list[Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in objects:
        records.extend(_flatten_records(item))
    return records


def _flatten_records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        rows: list[dict[str, Any]] = []
        for item in value:
            rows.extend(_flatten_records(item))
        return rows
    if not isinstance(value, dict):
        return []
    if _techniques_from_mapping(value):
        return [value]
    for key in ("events", "records", "data", "labels", "objects"):
        nested = value.get(key)
        if isinstance(nested, list):
            rows = _flatten_records(nested)
            if rows:
                return rows
    return []


def _sort_records_by_time(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(record: dict[str, Any]) -> str:
        for field in TIME_FIELDS:
            value = record.get(field)
            if value is not None:
                return str(value)
        return ""

    if any(key(record) for record in records):
        return sorted(records, key=key)
    return records


def _techniques_from_mapping(record: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    for key, value in record.items():
        normalized_key = str(key).lower()
        if any(hint in normalized_key for hint in TECHNIQUE_FIELD_HINTS):
            values.append(value)
    if not values:
        values = list(record.values())
    techniques: list[str] = []
    for value in values:
        techniques.extend(_techniques_from_value(value))
    return techniques


def _techniques_from_value(value: Any) -> list[str]:
    if isinstance(value, str):
        return _techniques_from_text_blob(value)
    if isinstance(value, list):
        return [technique for item in value for technique in _techniques_from_value(item)]
    if isinstance(value, dict):
        return [technique for item in value.values() for technique in _techniques_from_value(item)]
    return []


def _techniques_from_text_blob(text: str) -> list[str]:
    return attack_technique_ids_from_text(text)


if __name__ == "__main__":
    raise SystemExit(main())
