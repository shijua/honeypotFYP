"""Profiler domain logic for turning events into attacker profiles.

This module translates one Falco event into zero or more ATT&CK-aligned
evidence records, then rebuilds the current profile snapshot for the attacker.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from libs.common.config import RuntimeConfig
from libs.contracts.models import (
    EvidenceIngestRequest,
    EvidenceIngestResponse,
    FalcoEvent,
    ProfileSnapshot,
    TechniqueEvidence,
)
from services.profiler.attack_catalog import AttackCatalog
from services.profiler.repository import EvidenceRepository, ProfileRepository


class ProfileNotFoundError(KeyError):
    """Raised when a profile for attacker_key does not exist."""

    pass


@dataclass(frozen=True)
class AttackMapping:
    """Intermediate ATT&CK mapping derived from one Falco event.

    Example:
        AttackMapping(tech_id="T1003", tactic="Credential Access", reason="Read sensitive file: ...")
    """

    tech_id: str | None
    reason: str
    tactic: str | None = None


class ProfilerService:
    """Translate Falco events into ATT&CK evidence and attacker profiles."""

    _TECHNIQUE_TAG_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

    def __init__(
        self,
        evidence_repository: EvidenceRepository,
        profile_repository: ProfileRepository,
        attack_catalog: AttackCatalog,
        config: RuntimeConfig | None = None,
    ) -> None:
        self._evidence_repository = evidence_repository
        self._profile_repository = profile_repository
        self._attack_catalog = attack_catalog
        self._config = config or RuntimeConfig()

    def ingest(self, request: EvidenceIngestRequest) -> EvidenceIngestResponse:
        # Expand one event into evidence, then rebuild the profile.
        evidences = self._map_event(
            attacker_key=request.attacker_key,
            binding_id=request.binding_id,
            event=request.event,
        )
        self._evidence_repository.add_many(request.attacker_key, evidences)
        snapshot = self._rebuild_profile(request.attacker_key)
        return EvidenceIngestResponse(
            attacker_key=request.attacker_key,
            binding_id=request.binding_id,
            evidences=evidences,
            profile=snapshot,
        )

    def get_profile(self, attacker_key: str) -> ProfileSnapshot:
        snapshot = self._profile_repository.get(attacker_key)
        if snapshot is None:
            raise ProfileNotFoundError(attacker_key)
        return snapshot

    def _map_event(
        self,
        attacker_key: str,
        binding_id: str,
        event: FalcoEvent,
    ) -> list[TechniqueEvidence]:
        # Derive ATT&CK mapping and weight once per event.
        mappings = self._derive_attack_mappings(event)
        weight = self._priority_to_weight(event.priority)
        source_ref = self._build_source_ref(event)

        return [
            TechniqueEvidence(
                evidence_id=str(uuid4()),
                ts=_utc_aware(event.ts),
                attacker_key=attacker_key,
                binding_id=binding_id,
                tech_id=mapping.tech_id,
                group=(
                    mapping.tactic
                    or (
                        self._attack_catalog.tactic_for_technique(mapping.tech_id)
                        if mapping.tech_id
                        else None
                    )
                ),
                weight=weight,
                success=self._infer_success(event),
                reason=mapping.reason,
                source_ref=source_ref,
            )
            for mapping in mappings
        ]

    def _rebuild_profile(self, attacker_key: str) -> ProfileSnapshot:
        # Rebuild from stored evidence to keep aggregation deterministic.
        evidences = sorted(
            self._evidence_repository.list_by_attacker(attacker_key),
            key=lambda evidence: _utc_aware(evidence.ts),
        )
        if not evidences:
            snapshot = ProfileSnapshot(attacker_key=attacker_key)
            return self._profile_repository.upsert(snapshot)

        tactic_evidences = [
            evidence for evidence in evidences if evidence.group is not None
        ]
        conf_by_tactic, level_by_tactic = self._summarize_dimension(
            evidences=tactic_evidences,
            key_fn=lambda evidence: evidence.group,
        )
        technique_evidences = [
            evidence for evidence in evidences if evidence.tech_id is not None
        ]
        conf_by_technique, level_by_technique = self._summarize_dimension(
            evidences=technique_evidences,
            key_fn=lambda evidence: evidence.tech_id,
        )

        latest_ts = _utc_aware(evidences[-1].ts)
        recent_cutoff = latest_ts - timedelta(
            seconds=self._config.chain_window_seconds
        )
        # Keep recent history bounded for controller input.
        recent_evidences = [
            evidence for evidence in evidences if _utc_aware(evidence.ts) >= recent_cutoff
        ]

        snapshot = ProfileSnapshot(
            attacker_key=attacker_key,
            conf_by_tactic=conf_by_tactic,
            conf_by_technique=conf_by_technique,
            level_by_tactic=level_by_tactic,
            level_by_technique=level_by_technique,
            recent_tactics=self._dedupe_preserve(
                evidence.group
                for evidence in recent_evidences
                if evidence.group is not None
            ),
            recent_techniques=self._dedupe_preserve(
                evidence.tech_id
                for evidence in recent_evidences
                if evidence.tech_id is not None
            ),
            recent_evidence_ids=[
                evidence.evidence_id for evidence in recent_evidences[-5:]],
            updated_at=latest_ts,
        )
        return self._profile_repository.upsert(snapshot)

    def _summarize_dimension(
        self,
        evidences: list[TechniqueEvidence],
        key_fn,
    ) -> tuple[dict[str, float], dict[str, int]]:
        # Reuse the same grouping logic for tactics and techniques.
        grouped: dict[str, list[TechniqueEvidence]] = defaultdict(list)
        for evidence in evidences:
            grouped[key_fn(evidence)].append(evidence)

        confidences: dict[str, float] = {}
        levels: dict[str, int] = {}
        for key, items in grouped.items():
            count = len(items)
            avg_weight = sum(item.weight for item in items) / count
            # Log scaling dampens repeated noisy events.
            score = avg_weight * math.log1p(count)
            confidences[key] = round(1 - math.exp(-score), 4)
            levels[key] = self._level_for_count(count)

        return confidences, levels

    def _priority_to_weight(self, priority: str) -> float:
        # Use Falco priority as a simple evidence weight.
        weights = {
            "EMERGENCY": 4.0,
            "ALERT": 3.8,
            "CRITICAL": 3.5,
            "ERROR": 3.0,
            "WARNING": 2.5,
            "NOTICE": 2.0,
            "INFO": 1.5,
            "DEBUG": 1.0,
        }
        return weights.get(priority.upper(), 1.0)

    def _derive_attack_mappings(self, event: FalcoEvent) -> list[AttackMapping]:
        # Trust explicit ATT&CK tags and let the catalog resolve tactic names.
        tactic = self._tactic_from_tags(event.tags)
        tech_ids = self._technique_ids_from_tags(event.tags)
        if tactic and tech_ids:
            return [
                AttackMapping(
                    tech_id=tech_id,
                    reason=f"{event.falco_rule}: {event.output}",
                    tactic=tactic,
                )
                for tech_id in tech_ids
            ]
        if tech_ids:
            return [
                self._mapping_for_technique(
                    tech_id=tech_id,
                    reason=f"{event.falco_rule}: {event.output}",
                    tagged_tactic=tactic,
                )
                for tech_id in tech_ids
            ]

        if tactic is not None:
            return [
                AttackMapping(
                    tech_id=None,
                    reason=f"Tag-only tactic mapping for rule {event.falco_rule}",
                    tactic=tactic,
                )
            ]

        # Without ATT&CK tags, keep the fallback unclassified. TODO
        return [
            AttackMapping(
                tech_id=None,
                reason=f"Fallback mapping for rule {event.falco_rule}",
                tactic=None,
            )
        ]

    def _tactic_from_tags(self, tags: list[str]) -> str | None:
        for tag in tags:
            if tag.startswith("mitre_"):
                raw = tag[len("mitre_"):]
                return self._attack_catalog.canonical_tactic_name(raw)
        return None

    def _technique_ids_from_tags(self, tags: list[str]) -> list[str]:
        # Accept only canonical ATT&CK technique tags.
        return [tag for tag in tags if self._TECHNIQUE_TAG_RE.match(tag)]

    def _mapping_for_technique(
        self,
        tech_id: str,
        reason: str,
        tagged_tactic: str | None,
    ) -> AttackMapping:
        return AttackMapping(
            tech_id=tech_id,
            reason=reason,
            tactic=tagged_tactic or self._attack_catalog.tactic_for_technique(tech_id),
        )

    def _infer_success(self, event: FalcoEvent) -> bool:
        # Infer success from obvious failure language.
        text = f"{event.output} {event.falco_rule}".lower()
        return "failed" not in text and "denied" not in text

    def _build_source_ref(self, event: FalcoEvent) -> dict[str, object]:
        # Keep a compact evidence reference for later decisions.
        source_ref = {
            "falco_rule": event.falco_rule,
            "priority": event.priority,
            "output": event.output,
            "ts": event.ts.isoformat(),
        }
        if event.hostname:
            source_ref["hostname"] = event.hostname
        for key in ("proc_cmdline", "proc_name", "fd_name"):
            if key in event.output_fields:
                source_ref[key] = event.output_fields[key]
        return source_ref

    def _level_for_count(self, count: int) -> int:
        # Map repeated observations into a coarse level bucket.
        if count >= self._config.level2_threshold:
            return 3
        if count >= 2:
            return 2
        return 1

    def _dedupe_preserve(self, values) -> list[str]:
        # Preserve order while dropping duplicates.
        ordered: list[str] = []
        for value in values:
            if value not in ordered:
                ordered.append(value)
        return ordered


def _utc_aware(value: datetime) -> datetime:
    """Normalize naive and aware datetimes to comparable UTC-aware values."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
