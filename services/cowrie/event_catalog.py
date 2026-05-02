"""Config-backed mapping from Cowrie event ids to normalized telemetry fields.

The Cowrie domain service uses this catalog instead of hard-coding event
priorities, ATT&CK tags, descriptive tags, or profiler output fields in
business logic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class CowrieEventMapping:
    """Normalized mapping rules for one Cowrie event id.

    `mitre_*` and `Txxxx` tags are only used when the event behavior is clear.
    Less certain events can keep `tags=()` or use descriptive `cowrie_*` tags
    that are retained on observations but ignored by the ATT&CK profiler.
    `profile=False` means the event is stored for debugging/replay but does not
    create profiler evidence.

    Example:
        CowrieEventMapping(priority="INFO", tags=("cowrie_client_metadata",), profile=False)
    """

    priority: str
    tags: tuple[str, ...]
    output_template: str
    output_fields: tuple[str, ...]
    command_field: str | None = None
    profile: bool = False


class CowrieEventCatalog(Protocol):
    """Lookup contract for Cowrie event mapping rules.

    Example:
        mapping_for("cowrie.command.input").tags -> ("cowrie_command_input",)
    """

    def mapping_for(self, eventid: str) -> CowrieEventMapping:
        """Return mapping rules for one Cowrie event id."""
        ...


class FileCowrieEventCatalog:
    """JSON-backed Cowrie event mapping catalog."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._loaded = False
        self._default_mapping: CowrieEventMapping | None = None
        self._mappings: dict[str, CowrieEventMapping] = {}

    def mapping_for(self, eventid: str) -> CowrieEventMapping:
        self._ensure_loaded()
        if self._default_mapping is None:
            raise RuntimeError("Cowrie event catalog was not loaded")
        return self._mappings.get(eventid, self._default_mapping)

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return

        payload = json.loads(self._path.read_text(encoding="utf-8"))
        self._default_mapping = _mapping_from_payload(payload.get("default", {}))
        self._mappings = {
            eventid: _mapping_from_payload(item)
            for eventid, item in payload.get("events", {}).items()
        }
        self._loaded = True


def _mapping_from_payload(payload: object) -> CowrieEventMapping:
    if not isinstance(payload, dict):
        payload = {}
    return CowrieEventMapping(
        priority=str(payload.get("priority", "INFO")),
        tags=tuple(str(tag) for tag in payload.get("tags", [])),
        output_template=str(payload.get("output_template", "{eventid} from {src_ip}")),
        output_fields=tuple(
            str(field) for field in payload.get("output_fields", ())
        ),
        command_field=(
            str(payload["command_field"])
            if payload.get("command_field") is not None
            else None
        ),
        profile=bool(payload.get("profile", False)),
    )
