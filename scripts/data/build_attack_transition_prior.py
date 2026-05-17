#!/usr/bin/env python3
"""Build a technique transition prior from local ATT&CK-labelled datasets.

The builder is intentionally strict at the final step: records without a public
ATT&CK technique id are counted in the report but are not used for transition
counts. The default model is a trace-balanced bigram prior with a small global
fallback, while event-count mode remains available for baseline comparison.

Example:
    python scripts/data/build_attack_transition_prior.py vendor/datasets/casinolimit
"""

from __future__ import annotations

import argparse
import bz2
import csv
import io
import json
import re
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal

import yaml

from libs.common.config import RuntimeConfig
from libs.common.iterables import dedupe_preserve


TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
SUPPORTED_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".zip", ".bz2"}
CountMode = Literal["trace-balanced", "event-count"]


@dataclass(frozen=True)
class NormalizedEvent:
    """One ATT&CK-labelled event after dataset-specific parsing.

    Example:
        NormalizedEvent(case_id="scenario-1", technique="T1552.001", tactic="Credential Access")
    """

    case_id: str
    source_dataset: str
    technique: str
    tactic: str | None = None
    ts: str | None = None
    host_or_service: str | None = None
    procedure_text: str | None = None
    order: int = 0

    @property
    def sort_key(self) -> tuple[str, int]:
        """Return a stable timestamp/order key for direct-follow counts."""
        parsed = _parse_timestamp(self.ts)
        if parsed is None:
            return ("9999-12-31T23:59:59+00:00", self.order)
        return (parsed.isoformat(), self.order)


@dataclass
class BuildStats:
    """Counters used to explain which records influenced the prior.

    Example:
        records_seen["mordor"] == 20 and skipped_without_technique["mordor"] == 3
        means 17 Mordor records were eligible for transition training.
    """

    records_seen: Counter[str] = field(default_factory=Counter)
    events_used: Counter[str] = field(default_factory=Counter)
    skipped_without_technique: Counter[str] = field(default_factory=Counter)
    files_read: Counter[str] = field(default_factory=Counter)
    parse_errors: list[dict[str, str]] = field(default_factory=list)


def main() -> None:
    """CLI entrypoint: load public datasets, build the prior, and write JSON files.

    Example:
        python scripts/data/build_attack_transition_prior.py vendor/datasets/mordor --output data/transitions/technique_transition_prior.json
    """
    config = RuntimeConfig.from_env()
    parser = argparse.ArgumentParser(
        description="Build P(next ATT&CK technique | current technique) from local public datasets.",
    )
    parser.add_argument("inputs", nargs="+", help="Dataset files, directories, or zip archives.")
    parser.add_argument(
        "--output",
        default=config.attack_transition_prior_path,
        help="Output JSON path for the derived transition prior.",
    )
    parser.add_argument(
        "--report-output",
        default="data/transitions/technique_transition_prior_report.json",
        help="Output JSON path for build stats and skipped-record counts.",
    )
    parser.add_argument(
        "--normalized-output",
        default=None,
        help="Optional JSON path for normalized traces. Omit for large dataset builds.",
    )
    parser.add_argument("--alpha", type=float, default=0.1, help="Additive smoothing value.")
    parser.add_argument(
        "--min-support",
        type=int,
        default=1,
        help="Minimum raw transition count to include in the prior.",
    )
    parser.add_argument(
        "--count-mode",
        choices=("trace-balanced", "event-count"),
        default="trace-balanced",
        help="Transition-counting strategy. trace-balanced is the runtime default; event-count is the baseline.",
    )
    parser.add_argument(
        "--global-fallback-weight",
        type=float,
        default=0.05,
        help="Small destination-popularity fallback mixed into each source technique prior.",
    )
    args = parser.parse_args()

    events, stats = load_events([Path(item) for item in args.inputs])
    prior, report = build_prior(
        events,
        stats=stats,
        alpha=args.alpha,
        min_support=args.min_support,
        count_mode=args.count_mode,
        global_fallback_weight=args.global_fallback_weight,
    )

    output_path = Path(args.output)
    report_path = Path(args.report_output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(prior, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.normalized_output:
        normalized_path = Path(args.normalized_output)
        normalized_path.parent.mkdir(parents=True, exist_ok=True)
        normalized_path.write_text(
            json.dumps(build_normalized_traces(events), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote normalized traces to {normalized_path}")
    print(f"Wrote transition prior to {output_path}")
    print(f"Wrote build report to {report_path}")


def load_events(paths: list[Path]) -> tuple[list[NormalizedEvent], BuildStats]:
    """Load normalized events from dataset paths.

    Example:
        Input:
            [Path("vendor/datasets/mordor/compound/case/metadata.yaml")]
        Output:
            ([NormalizedEvent(case_id="...", technique="T1552.001", ...)], BuildStats(...))
    """
    stats = BuildStats()
    events: list[NormalizedEvent] = []
    order = 0
    for path in paths:
        for record, source_dataset, source_file in _iter_records(path, stats):
            stats.records_seen[source_dataset] += 1
            techniques = _techniques_from_record(record)
            if not techniques:
                stats.skipped_without_technique[source_dataset] += 1
                continue
            tactic = _tactic_from_record(record)
            for technique_index, technique in enumerate(techniques):
                events.append(
                    NormalizedEvent(
                        case_id=_case_id(record, source_file, source_dataset=source_dataset),
                        source_dataset=source_dataset,
                        technique=technique,
                        tactic=tactic,
                        ts=_first_string(record, ("timestamp", "ts", "time", "@timestamp", "event_time", "date", "datetime")),
                        host_or_service=_first_string(
                            record,
                            ("host", "hostname", "service", "host_or_service", "dst_host", "src_ip_zeek", "dest_ip_zeek"),
                        ),
                        procedure_text=_procedure_text(record),
                        order=_record_order(record, fallback=order) + technique_index,
                    )
                )
                stats.events_used[source_dataset] += 1
                order += 1
    return events, stats


def build_prior(
    events: list[NormalizedEvent],
    *,
    stats: BuildStats,
    alpha: float,
    min_support: int,
    count_mode: CountMode = "trace-balanced",
    global_fallback_weight: float = 0.05,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a smoothed transition-prior payload plus a diagnostic report.

    Example:
        Input:
            events=[T1552.001 -> T1046 in case-a, T1552.001 -> T1005 in case-b]
            count_mode="trace-balanced"
        Output:
            prior["transitions"]["T1552.001"] with probabilities for T1046 and T1005
    """
    traces: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        traces[(event.source_dataset, event.case_id)].append(event)

    if not 0 <= global_fallback_weight <= 1:
        raise ValueError("global_fallback_weight must be between 0 and 1")
    if count_mode not in ("trace-balanced", "event-count"):
        raise ValueError("count_mode must be trace-balanced or event-count")

    raw_transition_counts: dict[str, Counter[str]] = defaultdict(Counter)
    weighted_transition_counts: dict[str, Counter[str]] = defaultdict(Counter)
    trace_support: Counter[tuple[str, str]] = Counter()
    transition_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    raw_order2_counts: dict[str, Counter[str]] = defaultdict(Counter)
    weighted_order2_counts: dict[str, Counter[str]] = defaultdict(Counter)
    order2_trace_support: Counter[tuple[str, str]] = Counter()
    order2_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    raw_order3_counts: dict[str, Counter[str]] = defaultdict(Counter)
    weighted_order3_counts: dict[str, Counter[str]] = defaultdict(Counter)
    order3_trace_support: Counter[tuple[str, str]] = Counter()
    order3_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    for (source_dataset, _case_id_value), trace_events in traces.items():
        ordered_techniques = _ordered_trace_techniques(trace_events)
        local_counts: dict[str, Counter[str]] = defaultdict(Counter)
        local_order2_counts: dict[str, Counter[str]] = defaultdict(Counter)
        local_order3_counts: dict[str, Counter[str]] = defaultdict(Counter)
        previous: str | None = None
        for technique in ordered_techniques:
            if previous is not None and previous != technique:
                raw_transition_counts[previous][technique] += 1
                local_counts[previous][technique] += 1
                transition_sources[(previous, technique)].add(source_dataset)
            previous = technique
        for index in range(2, len(ordered_techniques)):
            source = f"{ordered_techniques[index - 2]}|{ordered_techniques[index - 1]}"
            destination = ordered_techniques[index]
            raw_order2_counts[source][destination] += 1
            local_order2_counts[source][destination] += 1
            order2_sources[(source, destination)].add(source_dataset)
        for index in range(3, len(ordered_techniques)):
            source = "|".join(ordered_techniques[index - 3 : index])
            destination = ordered_techniques[index]
            raw_order3_counts[source][destination] += 1
            local_order3_counts[source][destination] += 1
            order3_sources[(source, destination)].add(source_dataset)
        _add_weighted_counts(
            local_counts,
            weighted_transition_counts,
            trace_support,
            count_mode=count_mode,
        )
        _add_weighted_counts(
            local_order2_counts,
            weighted_order2_counts,
            order2_trace_support,
            count_mode=count_mode,
        )
        _add_weighted_counts(
            local_order3_counts,
            weighted_order3_counts,
            order3_trace_support,
            count_mode=count_mode,
        )

    global_destination_counts: Counter[str] = Counter()
    for destinations in raw_transition_counts.values():
        for destination, count in destinations.items():
            if count >= min_support:
                global_destination_counts[destination] += count
    global_total = sum(global_destination_counts.values())
    global_probability = {
        destination: count / global_total
        for destination, count in global_destination_counts.items()
        if global_total > 0
    }

    transitions = _build_transition_payload(
        weighted_transition_counts,
        raw_transition_counts,
        trace_support,
        transition_sources,
        min_support=min_support,
        alpha=alpha,
        global_probability=global_probability if global_fallback_weight > 0 else None,
        global_fallback_weight=global_fallback_weight,
    )
    order2_transitions = _build_transition_payload(
        weighted_order2_counts,
        raw_order2_counts,
        order2_trace_support,
        order2_sources,
        min_support=min_support,
        alpha=alpha,
    )
    order3_transitions = _build_transition_payload(
        weighted_order3_counts,
        raw_order3_counts,
        order3_trace_support,
        order3_sources,
        min_support=min_support,
        alpha=alpha,
    )

    top_transitions = _top_transition_rows(transitions)
    top_order2_transitions = _top_transition_rows(order2_transitions)
    top_order3_transitions = _top_transition_rows(order3_transitions)

    prior = {
        "schema_version": "v1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sources": sorted(stats.events_used),
        "alpha": alpha,
        "min_support": min_support,
        "count_mode": count_mode,
        "global_fallback_weight": global_fallback_weight,
        "transitions": transitions,
        "order2_transitions": order2_transitions,
        "order3_transitions": order3_transitions,
    }
    report = {
        "schema_version": "v1",
        "generated_at": prior["generated_at"],
        "source_counts": {
            source: {
                "records_seen": stats.records_seen[source],
                "events_used": stats.events_used[source],
                "skipped_without_technique": stats.skipped_without_technique[source],
                "files_read": stats.files_read[source],
            }
            for source in sorted(stats.records_seen)
        },
        "trace_count": len(traces),
        "transition_count": sum(len(destinations) for destinations in transitions.values()),
        "order2_transition_count": sum(len(destinations) for destinations in order2_transitions.values()),
        "order3_transition_count": sum(len(destinations) for destinations in order3_transitions.values()),
        "labelled_events_used": sum(stats.events_used.values()),
        "skipped_events_without_technique": sum(stats.skipped_without_technique.values()),
        "count_mode": count_mode,
        "global_fallback_weight": global_fallback_weight,
        "top_transitions": top_transitions[:25],
        "top_order2_transitions": top_order2_transitions[:25],
        "top_order3_transitions": top_order3_transitions[:25],
        "parse_errors": stats.parse_errors,
    }
    return prior, report


def _add_weighted_counts(
    local_counts: dict[str, Counter[str]],
    weighted_counts: dict[str, Counter[str]],
    trace_support: Counter[tuple[str, str]],
    *,
    count_mode: CountMode,
) -> None:
    """Add one trace's local transition counts to global counters.

    Example:
        Input:
            local_counts={"T1001|T1002": Counter({"T1003": 2, "T1004": 1})}, count_mode="trace-balanced"
        Output:
            weighted_counts["T1001|T1002"]["T1003"] += 0.666667
    """
    for source, destinations in local_counts.items():
        local_total = sum(destinations.values())
        if local_total <= 0:
            continue
        for destination, count in destinations.items():
            trace_support[(source, destination)] += 1
            if count_mode == "trace-balanced":
                weighted_counts[source][destination] += count / local_total
            else:
                weighted_counts[source][destination] += count


def _build_transition_payload(
    weighted_counts: dict[str, Counter[str]],
    raw_counts: dict[str, Counter[str]],
    trace_support: Counter[tuple[str, str]],
    transition_sources: dict[tuple[str, str], set[str]],
    *,
    min_support: int,
    alpha: float,
    global_probability: dict[str, float] | None = None,
    global_fallback_weight: float = 0.0,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Build transition JSON for order-1 or order-2 sources.

    Example:
        Input:
            weighted_counts={"T1001|T1002": Counter({"T1003": 1.0})}
        Output:
            {"T1001|T1002": {"T1003": {"probability": 1.0, "support": 1, ...}}}
    """
    transitions: dict[str, dict[str, dict[str, Any]]] = {}
    for source, destinations in sorted(weighted_counts.items()):
        eligible = {
            destination: count
            for destination, count in destinations.items()
            if raw_counts[source][destination] >= min_support
        }
        if not eligible:
            continue
        total = sum(eligible.values())
        denominator = total + (len(eligible) * alpha)
        local_probability = {
            destination: (count + alpha) / denominator
            for destination, count in eligible.items()
        }
        destinations_to_emit = set(eligible)
        if global_probability:
            destinations_to_emit.update(global_probability)
        transitions[source] = {}
        for destination in sorted(destinations_to_emit):
            local_value = local_probability.get(destination, 0.0)
            fallback_value = (global_probability or {}).get(destination, 0.0)
            probability = ((1 - global_fallback_weight) * local_value) + (global_fallback_weight * fallback_value)
            if probability <= 0:
                continue
            fallback_only = destination not in eligible
            transitions[source][destination] = {
                "count": _json_count(destinations.get(destination, 0.0)),
                "probability": round(probability, 6),
                "support": int(raw_counts[source][destination]),
                "trace_support": int(trace_support[(source, destination)]),
                "sources": sorted(transition_sources[(source, destination)]) if not fallback_only else ["global_fallback"],
            }
            if fallback_only:
                transitions[source][destination]["fallback"] = True
    return transitions


def _top_transition_rows(transitions: dict[str, dict[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    rows = [
        {
            "from_technique": source,
            "to_technique": destination,
            **payload,
        }
        for source, destinations in transitions.items()
        for destination, payload in destinations.items()
    ]
    rows.sort(key=lambda item: (-item["probability"], -float(item["count"]), item["from_technique"], item["to_technique"]))
    return rows


def build_normalized_traces(events: list[NormalizedEvent]) -> dict[str, Any]:
    """Return normalized trace-schema JSON from loaded labelled events.

    Example:
        Input:
            [NormalizedEvent(case_id="case-a", source_dataset="mordor", technique="T1552.001")]
        Output:
            {"traces": [{"case_id": "case-a", "events": [{"technique": "T1552.001"}]}]}
    """
    traces: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        traces[(event.source_dataset, event.case_id)].append(event)
    return {
        "schema_version": "v1",
        "traces": [
            {
                "case_id": case_id,
                "source_dataset": source_dataset,
                "events": [
                    {
                        "ts": event.ts,
                        "technique": event.technique,
                        "tactic": event.tactic,
                        "host_or_service": event.host_or_service,
                        "procedure_text": event.procedure_text,
                    }
                    for event in sorted(trace_events, key=lambda item: item.sort_key)
                ],
            }
            for (source_dataset, case_id), trace_events in sorted(traces.items())
        ],
    }


def _iter_records(path: Path, stats: BuildStats) -> Iterable[tuple[dict[str, Any], str, str]]:
    """Yield raw dict records from files, directories, `.zip`, or `.bz2` inputs.

    Example:
        Path("vendor/datasets/mordor") -> yields each CSV/JSON/YAML record found recursively.
        Path("case.zip") -> yields supported member records as `("mordor", "case.zip:member.json")`.
    """
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file() and child.suffix.lower() in SUPPORTED_SUFFIXES:
                yield from _iter_records(child, stats)
        return
    source_dataset = _source_dataset(path)
    if path.suffix.lower() == ".zip":
        yield from _iter_zip_records(path, source_dataset, stats)
        return
    if path.suffix.lower() == ".bz2":
        inner_suffix = path.with_suffix("").suffix.lower()
        if inner_suffix not in SUPPORTED_SUFFIXES - {".zip", ".bz2"}:
            stats.parse_errors.append({"source_dataset": source_dataset, "source_file": str(path), "error": "unsupported bz2 payload suffix"})
            return
        yield from _records_from_bytes(
            bz2.decompress(path.read_bytes()),
            suffix=inner_suffix,
            source_dataset=source_dataset,
            source_file=str(path),
            stats=stats,
        )
        return
    yield from _records_from_bytes(
        path.read_bytes(),
        suffix=path.suffix.lower(),
        source_dataset=source_dataset,
        source_file=str(path),
        stats=stats,
    )


def _iter_zip_records(path: Path, source_dataset: str, stats: BuildStats) -> Iterable[tuple[dict[str, Any], str, str]]:
    """Read supported files inside one zip without extracting it to disk.

    Example:
        case.zip containing `metadata.yaml` and `events.jsonl` yields records from both files.
    """
    with zipfile.ZipFile(path) as archive:
        for member in sorted(archive.namelist()):
            suffix = Path(member).suffix.lower()
            if suffix not in SUPPORTED_SUFFIXES - {".zip"}:
                continue
            with archive.open(member) as handle:
                yield from _records_from_bytes(
                    handle.read(),
                    suffix=suffix,
                    source_dataset=source_dataset,
                    source_file=f"{path}:{member}",
                    stats=stats,
                )


def _records_from_bytes(
    payload: bytes,
    *,
    suffix: str,
    source_dataset: str,
    source_file: str,
    stats: BuildStats,
) -> Iterable[tuple[dict[str, Any], str, str]]:
    """Parse one supported file payload into raw dict records.

    Example:
        suffix=".jsonl", payload=b'{"technique":"T1083"}\n' -> yields {"technique": "T1083"}.
    """
    stats.files_read[source_dataset] += 1
    text = payload.decode("utf-8", errors="replace")
    try:
        if suffix == ".csv":
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                yield dict(row), source_dataset, source_file
        elif suffix in {".jsonl", ".ndjson"}:
            for line in text.splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                if isinstance(item, dict):
                    yield item, source_dataset, source_file
        elif suffix == ".json":
            yield from _flatten_records(json.loads(text), source_dataset, source_file)
        elif suffix in {".yaml", ".yml"}:
            yield from _flatten_records(yaml.safe_load(text), source_dataset, source_file)
    except Exception as exc:
        stats.parse_errors.append(
            {
                "source_dataset": source_dataset,
                "source_file": source_file,
                "error": str(exc),
            }
        )


def _flatten_records(payload: Any, source_dataset: str, source_file: str) -> Iterable[tuple[dict[str, Any], str, str]]:
    """Yield dict records from common nested dataset shapes.

    Example:
        {"events": [{"technique": "T1083"}]} -> yields the inner event.
        {"label-1": {"technique": "T1005"}} -> yields {"record_id": "label-1", "technique": "T1005"}.
    """
    if isinstance(payload, dict):
        yielded = False
        for key in ("events", "records", "data", "rows", "objects", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                yielded = True
                for item in value:
                    if isinstance(item, dict):
                        yield item, source_dataset, source_file
        if not yielded and payload and all(isinstance(item, dict) for item in payload.values()):
            # CasinoLimit label files are keyed by label id, with each value carrying a technique.
            yielded = True
            for key, item in payload.items():
                yield {"record_id": str(key), **item}, source_dataset, source_file
        if not yielded:
            yield payload, source_dataset, source_file
        return
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item, source_dataset, source_file


def _source_dataset(path: Path) -> str:
    """Infer the dataset family from the path so reports can be source-grouped.

    Example:
        vendor/datasets/uwf-zeekdata24/http.json -> "uwf-zeekdata24".
    """
    parts = [part.lower() for part in path.parts]
    for candidate in ("mordor", "otrf", "pwnjutsu", "casinolimit", "windows-apt", "windowsapt", "uwf-zeekdata24", "uwf"):
        if any(candidate in part for part in parts):
            return candidate.replace("windowsapt", "windows-apt")
    return path.stem


def _techniques_from_record(record: dict[str, Any]) -> list[str]:
    """Extract ordered ATT&CK technique ids from one raw record.

    Example:
        Input:
            {"attack_mappings": [{"technique": "T1552", "sub-technique": "001"}]}
        Output:
            ["T1552.001"]
    """
    attack_mapping_techniques = _techniques_from_attack_mappings(record)
    if attack_mapping_techniques:
        return attack_mapping_techniques
    values: list[str] = []
    for key in (
        "technique",
        "technique_id",
        "label_technique",
        "attack_technique",
        "mitre_technique",
        "mitre_attack_technique",
        "mitre_attack_technique_id",
        "tags",
        "labels",
        "rule",
        "event",
        "message",
        "procedure",
        "procedure_text",
    ):
        if key in record:
            values.extend(_string_values(record[key]))
    if not values:
        values.extend(_string_values(record))
    techniques = []
    for value in values:
        techniques.extend(match.group(0) for match in TECHNIQUE_RE.finditer(value))
    return dedupe_preserve(techniques)


def _techniques_from_attack_mappings(record: dict[str, Any]) -> list[str]:
    """Read Mordor/OTRF-style `attack_mappings` records.

    Example:
        {"attack_mappings": [{"technique": "T1552", "sub-technique": "001"}]} -> ["T1552.001"]
    """
    mappings = record.get("attack_mappings")
    if not isinstance(mappings, list):
        return []
    techniques: list[str] = []
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        technique = str(mapping.get("technique") or "").strip()
        subtechnique = str(mapping.get("sub-technique") or mapping.get("sub_technique") or "").strip()
        if not TECHNIQUE_RE.fullmatch(technique):
            continue
        if subtechnique and subtechnique.isdigit() and "." not in technique:
            techniques.append(f"{technique}.{subtechnique.zfill(3)}")
        else:
            techniques.append(technique)
    return dedupe_preserve(techniques)


def _string_values(value: Any) -> list[str]:
    """Return all scalar strings nested inside a raw value.

    Example:
        {"tags": ["attack.T1083", {"message": "uses T1005"}]} -> ["attack.T1083", "uses T1005"]
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(_string_values(item))
        return result
    if isinstance(value, dict):
        result: list[str] = []
        for item in value.values():
            result.extend(_string_values(item))
        return result
    return []


def _case_id(record: dict[str, Any], source_file: str, *, source_dataset: str) -> str:
    """Choose a stable trace id for grouping events.

    Example:
        Input:
            record={"id": "SDWIN-test"}, source_dataset="mordor"
        Output:
            "SDWIN-test"
    """
    if source_dataset in {"mordor", "otrf"}:
        mordor_id = _first_string(record, ("id", "title"))
        if mordor_id:
            return mordor_id
    return (
        _first_string(
            record,
            (
                "case_id",
                "scenario_id",
                "scenario",
                "attack_id",
                "mission_id",
                "session",
                "trace_id",
                "team",
                "src_ip_zeek",
                "src_ip",
                "source_ip",
                "id.orig_h",
            ),
        )
        or Path(source_file).stem
    )


def _first_string(record: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """Return the first non-empty string from a preferred key list.

    Example:
        _first_string({"host": "", "hostname": "web01"}, ("host", "hostname")) -> "web01"
    """
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    return item.strip()
    return None


def _procedure_text(record: dict[str, Any]) -> str | None:
    """Pick a human-readable procedure/command field for normalized traces."""
    return _first_string(record, ("procedure_text", "procedure", "command", "process", "message", "description", "title"))


def _tactic_from_record(record: dict[str, Any]) -> str | None:
    """Extract the ATT&CK tactic when the dataset provides one.

    Example:
        {"attack_mappings": [{"tactics": ["Discovery"]}]} -> "Discovery"
    """
    mappings = record.get("attack_mappings")
    if isinstance(mappings, list):
        for mapping in mappings:
            if not isinstance(mapping, dict):
                continue
            tactics = mapping.get("tactics")
            if isinstance(tactics, list):
                for tactic in tactics:
                    if isinstance(tactic, str) and tactic.strip():
                        return tactic.strip()
            if isinstance(tactics, str) and tactics.strip():
                return tactics.strip()
    return _first_string(record, ("tactic", "tactics", "label_tactic", "kill_chain_phase", "phase"))


def _ordered_trace_techniques(trace_events: list[NormalizedEvent]) -> list[str]:
    """Return timestamp/order-sorted techniques with adjacent duplicates removed.

    Example:
        Input:
            [T1083(order=1), T1083(order=2), T1005(order=3)]
        Output:
            ["T1083", "T1005"]
    """
    ordered = sorted(trace_events, key=lambda item: item.sort_key)
    result: list[str] = []
    for event in ordered:
        if result and result[-1] == event.technique:
            continue
        result.append(event.technique)
    return result


def _json_count(value: float) -> int | float:
    """Emit whole-number counts as JSON ints and fractional weights as floats."""
    if float(value).is_integer():
        return int(value)
    return round(float(value), 6)


def _record_order(record: dict[str, Any], *, fallback: int) -> int:
    """Return a stable ordering hint when a dataset has event ids but no timestamp.

    Example:
        {"auditd_events": {"bastion": ["46738"]}} -> 46738
    """
    for key in ("order", "event_id", "eventid", "sequence"):
        value = record.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    auditd_events = record.get("auditd_events")
    event_ids: list[int] = []
    if isinstance(auditd_events, dict):
        for values in auditd_events.values():
            for value in _string_values(values):
                if value.strip().isdigit():
                    event_ids.append(int(value.strip()))
    if event_ids:
        return min(event_ids)
    return fallback


def _parse_timestamp(value: str | None) -> datetime | None:
    """Parse ISO-like timestamps and default naive timestamps to UTC.

    Example:
        "2026-04-27T12:00:00Z" -> datetime(..., tzinfo=UTC)
    """
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


if __name__ == "__main__":
    main()
