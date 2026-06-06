"""Profiler domain logic for turning events into attacker profiles.

This module translates one Falco event into zero or more ATT&CK-aligned
evidence records, then rebuilds the current profile snapshot for the attacker.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from uuid import uuid4

from libs.common.clock import utc_aware
from libs.common.config import RuntimeConfig
from libs.common.iterables import dedupe_preserve
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
                ts=utc_aware(event.ts),
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
            key=lambda evidence: utc_aware(evidence.ts),
        )
        if not evidences:
            snapshot = ProfileSnapshot(attacker_key=attacker_key)
            return self._profile_repository.upsert(snapshot)

        latest_ts = utc_aware(evidences[-1].ts)
        recent_cutoff = latest_ts - timedelta(
            seconds=self._config.chain_window_seconds
        )
        # Keep recent history bounded for controller input.
        recent_evidences = [
            evidence for evidence in evidences if utc_aware(evidence.ts) >= recent_cutoff
        ]
        tactic_evidences = [
            evidence for evidence in recent_evidences if evidence.group is not None
        ]
        conf_by_tactic = self._summarize_dimension(
            evidences=tactic_evidences,
            key_fn=lambda evidence: evidence.group,
        )
        technique_evidences = [
            evidence for evidence in recent_evidences if evidence.tech_id is not None
        ]
        conf_by_technique = self._summarize_dimension(
            evidences=technique_evidences,
            key_fn=lambda evidence: evidence.tech_id,
        )

        snapshot = ProfileSnapshot(
            attacker_key=attacker_key,
            conf_by_tactic=conf_by_tactic,
            conf_by_technique=conf_by_technique,
            recent_tactics=dedupe_preserve(
                evidence.group
                for evidence in recent_evidences
                if evidence.group is not None
            ),
            recent_techniques=dedupe_preserve(
                evidence.tech_id
                for evidence in recent_evidences
                if evidence.tech_id is not None
            ),
            recent_evidence_ids=[
                evidence.evidence_id for evidence in recent_evidences[-5:]
            ],
            # Public HTTP evidence is kept separate from ATT&CK confidence so
            # the controller can use it as concrete breadcrumbs for dependencies.
            recent_public_http_paths=self._public_http_values(
                recent_evidences,
                "http_path",
            ),
            recent_public_http_rules=self._public_http_values(
                recent_evidences,
                "http_rule_names",
            ),
            recent_public_http_indicators=self._public_http_values(
                recent_evidences,
                "http_indicators",
            ),
            recent_internal_http_paths=self._internal_http_values(
                recent_evidences,
                "http_path",
            ),
            recent_internal_http_rules=self._internal_http_values(
                recent_evidences,
                "http_rule_names",
            ),
            recent_internal_http_indicators=self._internal_http_values(
                recent_evidences,
                "http_indicators",
            ),
            recent_asset_ids=self._source_ref_values(
                recent_evidences,
                "asset_id",
            ),
            updated_at=latest_ts,
        )
        return self._profile_repository.upsert(snapshot)

    def _summarize_dimension(
        self,
        evidences: list[TechniqueEvidence],
        key_fn,
    ) -> dict[str, float]:
        # Reuse the same grouping logic for tactics and techniques.
        grouped: dict[str, list[TechniqueEvidence]] = defaultdict(list)
        for evidence in evidences:
            grouped[key_fn(evidence)].append(evidence)

        confidences: dict[str, float] = {}
        for key, items in grouped.items():
            # Repeated probes of the same path/command should not inflate
            # confidence; distinct evidence fingerprints still stack.
            weights_by_fingerprint: dict[tuple[object, ...], float] = {}
            for item in items:
                fingerprint = self._confidence_fingerprint(item)
                weights_by_fingerprint[fingerprint] = max(
                    weights_by_fingerprint.get(fingerprint, 0.0),
                    item.weight,
                )
            score = sum(weights_by_fingerprint.values())
            confidences[key] = round(1 - math.exp(-score), 4)

        return confidences

    def _confidence_fingerprint(self, evidence: TechniqueEvidence) -> tuple[object, ...]:
        """Return a stable evidence identity for confidence aggregation."""
        source_ref = evidence.source_ref
        keys = (
            "source",
            "asset_id",
            "event_type",
            "falco_rule",
            "proc_cmdline",
            "proc_name",
            "fd_name",
            "http_surface",
            "http_method",
            "http_path",
            "http_query_string",
            "http_user_agent",
            "http_rule_names",
            "http_indicators",
            "opencanary_service",
            "opencanary_logtype",
            "opencanary_command",
            "opencanary_commands",
            "opencanary_repo",
            "high_interaction_source",
            "high_interaction_service",
            "high_interaction_event_type",
            "username",
            "password_seen",
        )
        parts: list[object] = []
        for key in keys:
            if key not in source_ref:
                continue
            value = source_ref[key]
            if isinstance(value, list):
                parts.append((key, tuple(str(item) for item in value)))
            else:
                parts.append((key, str(value)))
        if parts:
            return tuple(parts)
        return ("reason", evidence.reason, evidence.success)

    def _priority_to_weight(self, priority: str) -> float:
        label = str(priority or "low").strip().lower()
        return {"low": 0.5, "medium": 1.0, "high": 2.0}.get(label, 0.5)

    def _derive_attack_mappings(self, event: FalcoEvent) -> list[AttackMapping]:
        # Interpret tags in order so a rule can emit
        # ["mitre_initial_access", "T1190", "mitre_discovery", "T1046"].
        # Each technique gets the nearest preceding tactic as context.
        mappings = self._mappings_from_tags(event)
        if mappings:
            return mappings

        # Untagged rules are preserved for audit but not forced into a tactic or
        # technique. This avoids inventing ATT&CK evidence when the adapter did
        # not provide a clear mapping.
        return [
            AttackMapping(
                tech_id=None,
                reason=f"Fallback mapping for rule {event.falco_rule}",
                tactic=None,
            )
        ]

    def _mappings_from_tags(self, event: FalcoEvent) -> list[AttackMapping]:
        """Convert ordered MITRE tags into tactic/technique evidence mappings."""
        reason = f"{event.falco_rule}: {event.output}"
        current_tactic: str | None = None
        tactic_only_mappings: list[AttackMapping] = []
        mappings: list[AttackMapping] = []
        seen_mapping_keys: set[tuple[str | None, str | None]] = set()

        for tag in event.tags:
            if not tag.startswith("mitre_"):
                if self._TECHNIQUE_TAG_RE.match(tag):
                    tactic = current_tactic or self._attack_catalog.tactic_for_technique(
                        tag
                    )
                    mapping_key = (tag, tactic)
                    if mapping_key not in seen_mapping_keys:
                        mappings.append(
                            AttackMapping(
                                tech_id=tag,
                                reason=reason,
                                tactic=tactic,
                            )
                        )
                        seen_mapping_keys.add(mapping_key)
                continue

            raw = tag[len("mitre_"):]
            current_tactic = self._attack_catalog.canonical_tactic_name(raw)
            mapping_key = (None, current_tactic)
            if current_tactic and mapping_key not in seen_mapping_keys:
                tactic_only_mappings.append(
                    AttackMapping(
                        tech_id=None,
                        reason=f"Tag-only tactic mapping for rule {event.falco_rule}",
                        tactic=current_tactic,
                    )
                )
                seen_mapping_keys.add(mapping_key)

        return mappings or tactic_only_mappings

    def _infer_success(self, event: FalcoEvent) -> bool:
        # Infer success from obvious failure language.
        text = f"{event.output} {event.falco_rule}".lower()
        return "failed" not in text and "denied" not in text

    def _build_source_ref(self, event: FalcoEvent) -> dict[str, object]:
        # Keep a compact evidence reference for dashboards and later controller
        # decisions without storing the whole raw adapter event.
        source_ref = {
            "falco_rule": event.falco_rule,
            "priority": event.priority,
            "output": event.output,
            "ts": event.ts.isoformat(),
        }
        if event.hostname:
            source_ref["hostname"] = event.hostname
        for key in (
            "proc_cmdline",
            "proc_name",
            "fd_name",
            "source",
            "asset_id",
            "event_type",
            "signature",
            "category",
            "severity",
            "src_ip",
            "src_port",
            "dest_ip",
            "dest_port",
            "proto",
            "http_hostname",
            "http_surface",
            "http_url",
            "http_method",
            "http_path",
            "http_query_string",
            "http_user_agent",
            "http_rule_names",
            "http_indicators",
            "http_evidence_labels",
            "opencanary_service",
            "opencanary_logtype",
            "opencanary_command",
            "opencanary_commands",
            "opencanary_repo",
            "high_interaction_source",
            "high_interaction_service",
            "high_interaction_event_type",
            "high_interaction_logdata",
            "username",
            "password_seen",
            "node_id",
        ):
            if key in event.output_fields:
                source_ref[key] = event.output_fields[key]
        return source_ref

    def _public_http_values(
        self,
        evidences: list[TechniqueEvidence],
        source_ref_key: str,
    ) -> list[str]:
        """Extract recent public-surface breadcrumbs from evidence source refs.

        Public portal requests are stored as normal evidence records, but only
        values with source="public_http" should drive file/path-based asset
        dependencies. This keeps Cowrie/OpenCanary evidence from accidentally
        satisfying HTTP breadcrumb gates.
        """
        values: list[str] = []
        for evidence in evidences:
            source_ref = evidence.source_ref
            if source_ref.get("source") != "public_http":
                continue
            value = source_ref.get(source_ref_key)
            if isinstance(value, list):
                values.extend(item for item in value if isinstance(item, str))
            elif isinstance(value, str) and value:
                values.append(value)
        return dedupe_preserve(values)

    def _internal_http_values(
        self,
        evidences: list[TechniqueEvidence],
        source_ref_key: str,
    ) -> list[str]:
        """Extract recent internal-asset HTTP breadcrumbs from evidence refs."""
        values: list[str] = []
        for evidence in evidences:
            source_ref = evidence.source_ref
            if source_ref.get("source") != "internal_http":
                continue
            value = source_ref.get(source_ref_key)
            if isinstance(value, list):
                values.extend(item for item in value if isinstance(item, str))
            elif isinstance(value, str) and value:
                values.append(value)
        return dedupe_preserve(values)

    def _source_ref_values(
        self,
        evidences: list[TechniqueEvidence],
        source_ref_key: str,
    ) -> list[str]:
        """Extract recent source-ref values without restricting telemetry source.

        Example:
            internal HTTP evidence with source_ref.asset_id=git-internal
            -> ["git-internal"].
        """
        values: list[str] = []
        for evidence in evidences:
            value = evidence.source_ref.get(source_ref_key)
            if isinstance(value, list):
                values.extend(item for item in value if isinstance(item, str))
            elif isinstance(value, str) and value:
                values.append(value)
        return dedupe_preserve(values)
