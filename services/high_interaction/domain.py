"""Domain logic for high-interaction honeypot telemetry.

Dionaea and Honeytrap expose different raw log formats, but their role
in this prototype is the same: once a same-port upgrade is active, convert real
backend interactions into low-noise ATT&CK evidence and preserve the asset id
that produced it.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from libs.common.iterables import dedupe_preserve
from libs.contracts.models import (
    EvidenceIngestRequest,
    FalcoEvent,
    HighInteractionIngestRequest,
    HighInteractionIngestResponse,
    HighInteractionLogEvent,
    HighInteractionObservation,
    ResolveBindingRequest,
)
from services.binding_service.domain import BindingService
from services.high_interaction.repository import HighInteractionObservationRepository
from services.high_interaction.sigma_mapping import FileHighInteractionSigmaRuleMatcher
from services.profiler.domain import ProfilerService


class HighInteractionService:
    """Ingest normalized high-interaction backend events.

    Example:
        Dionaea payload download -> Initial Access/Execution/C2 evidence.
    """

    def __init__(
        self,
        binding_service: BindingService,
        profiler_service: ProfilerService,
        observation_repository: HighInteractionObservationRepository,
        sigma_matcher: FileHighInteractionSigmaRuleMatcher | None = None,
    ) -> None:
        self._binding_service = binding_service
        self._profiler_service = profiler_service
        self._observation_repository = observation_repository
        self._sigma_matcher = sigma_matcher or FileHighInteractionSigmaRuleMatcher()

    def ingest(self, request: HighInteractionIngestRequest) -> HighInteractionIngestResponse:
        """Resolve the attacker, store an observation, and update the profile."""
        event = request.event
        tags = _profile_tags(event, self._sigma_matcher)
        binding = self._binding_service.resolve(
            ResolveBindingRequest(
                attacker_key=event.attacker_key,
                protocol=request.protocol,
            )
        )
        ingest_response = self._profiler_service.ingest(
            EvidenceIngestRequest(
                attacker_key=event.attacker_key,
                binding_id=binding.binding_id,
                event=FalcoEvent(
                    ts=event.ts,
                    falco_rule=f"{event.source} {event.service} {event.event_type}",
                    priority=_priority_for(event),
                    output=_format_output(event),
                    tags=tags,
                    output_fields={
                        "source": "high_interaction",
                        "asset_id": event.asset_id,
                        "event_type": event.event_type,
                        "high_interaction_source": event.source,
                        "high_interaction_service": event.service,
                        "high_interaction_event_type": event.event_type,
                        "high_interaction_logdata": _safe_logdata(event.logdata),
                        "src_ip": event.src_host or event.attacker_key,
                        "src_port": event.src_port,
                        "dest_ip": event.dst_host,
                        "dst_host": event.dst_host,
                        "dest_port": event.dst_port,
                        "dst_port": event.dst_port,
                    },
                ),
            )
        )
        observation = HighInteractionObservation(
            observation_id=str(uuid4()),
            ts=event.ts,
            attacker_key=event.attacker_key,
            binding_id=binding.binding_id,
            source=event.source,
            service=event.service,
            event_type=event.event_type,
            asset_id=event.asset_id,
            src_host=event.src_host,
            src_port=event.src_port,
            dst_host=event.dst_host,
            dst_port=event.dst_port,
            logdata=_safe_logdata(event.logdata),
            tags=tags,
            profiler_evidence_ids=[
                evidence.evidence_id for evidence in ingest_response.evidences
            ],
        )
        stored_observation = self._observation_repository.add(observation)
        return HighInteractionIngestResponse(
            observation=stored_observation,
            binding=binding,
            profile=ingest_response.profile,
        )


def _profile_tags(
    event: HighInteractionLogEvent,
    sigma_matcher: FileHighInteractionSigmaRuleMatcher,
) -> list[str]:
    """Map one normalized backend event into ATT&CK tags with Sigma rules.

    Example:
        source=dionaea, event_type=download.offer -> T1190, T1204.002, T1105, T1041.
    """
    base_tags = ["high_interaction", f"high_interaction_{event.source}", f"service_{event.service}"]
    sigma_tags = sigma_matcher.tags_for(event)
    return dedupe_preserve([*sigma_tags, *base_tags])


def _priority_for(event: HighInteractionLogEvent) -> str:
    text = _event_text(event)
    if _contains(text, "payload", "download", "upload", "exploit", "shellcode"):
        return "high"
    if _contains(text, "login", "auth", "password"):
        return "medium"
    return "low"


def _format_output(event: HighInteractionLogEvent) -> str:
    asset = f" asset={event.asset_id}" if event.asset_id else ""
    endpoint = f" {event.src_host or event.attacker_key}->{event.dst_host or '?'}:{event.dst_port or '?'}"
    return f"{event.source} {event.service} {event.event_type}{asset}{endpoint}"


def _safe_logdata(logdata: dict[str, Any]) -> dict[str, Any]:
    """Redact obvious credential fields before observations hit disk.

    Example:
        {"password": "secret", "function": "read"} -> {"password": "[redacted]", "function": "read"}
    """
    safe: dict[str, Any] = {}
    for key, value in logdata.items():
        lowered = str(key).lower()
        if any(token in lowered for token in ("pass", "secret", "token", "key", "auth")):
            safe[str(key)] = "[redacted]"
        else:
            safe[str(key)] = value
    return safe


def _event_text(event: HighInteractionLogEvent) -> str:
    return " ".join(
        [
            event.source,
            event.service,
            event.event_type,
            " ".join(str(value) for value in event.logdata.values()),
        ]
    ).lower()


def _contains(text: str, *needles: str) -> bool:
    return any(needle in text for needle in needles)
