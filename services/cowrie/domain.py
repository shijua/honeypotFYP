"""Domain logic for ingesting Cowrie SSH honeypot telemetry.

Cowrie provides attacker interaction logs from inside the SSH honeypot. This
adapter resolves the attacker binding, stores a sanitized observation, and
forwards a normalized event into the profiler.
"""

from __future__ import annotations

from uuid import uuid4

from libs.contracts.models import (
    CowrieIngestRequest,
    CowrieIngestResponse,
    CowrieLogEvent,
    CowrieObservation,
    EvidenceIngestRequest,
    FalcoEvent,
    ProfileSnapshot,
    ResolveBindingRequest,
    TechniqueEvidence,
)
from services.binding_service.domain import BindingService
from services.cowrie.command_mapping import CowrieCommandRuleCatalog
from services.cowrie.event_catalog import CowrieEventCatalog, CowrieEventMapping
from services.cowrie.repository import CowrieObservationRepository
from services.profiler.domain import ProfilerService, ProfileNotFoundError


class CowrieService:
    """Ingest Cowrie JSON events into the binding/profile pipeline.

    Example:
        ingest(cowrie.command.input with input="uname -a") -> Execution evidence
    """

    def __init__(
        self,
        binding_service: BindingService,
        profiler_service: ProfilerService,
        observation_repository: CowrieObservationRepository,
        event_catalog: CowrieEventCatalog,
        command_rule_catalog: CowrieCommandRuleCatalog,
    ) -> None:
        self._binding_service = binding_service
        self._profiler_service = profiler_service
        self._observation_repository = observation_repository
        self._event_catalog = event_catalog
        self._command_rule_catalog = command_rule_catalog

    def ingest(self, request: CowrieIngestRequest) -> CowrieIngestResponse:
        """Ingest one Cowrie event and update binding/profile state."""
        event = request.event
        # Cowrie src_ip is the attacker identity for the SSH entrypoint.
        binding = self._binding_service.resolve(
            ResolveBindingRequest(
                attacker_key=event.src_ip,
                protocol=request.protocol,
            )
        )
        # Event semantics live in data/cowrie/event_mappings.json, not here.
        mapping = self._event_catalog.mapping_for(event.eventid)
        tags = list(mapping.tags)
        evidences, profile = self._profile_event(
            event=event,
            binding_id=binding.binding_id,
            mapping=mapping,
            tags=tags,
            command_rule_catalog=self._command_rule_catalog,
        )

        # Store a sanitized intake record for research/debugging. Do not persist
        # raw password values; password_seen is enough for behavior analysis.
        observation = CowrieObservation(
            observation_id=str(uuid4()),
            ts=event.timestamp,
            attacker_key=event.src_ip,
            binding_id=binding.binding_id,
            eventid=event.eventid,
            session=event.session,
            sensor=event.sensor,
            username=event.username,
            password_seen=event.password is not None,
            command=_event_value(event, mapping.command_field),
            message=event.message,
            tags=tags,
            profiler_evidence_ids=[evidence.evidence_id for evidence in evidences],
        )
        stored_observation = self._observation_repository.add(observation)
        return CowrieIngestResponse(
            observation=stored_observation,
            binding=binding,
            profile=profile,
        )

    def _profile_event(
        self,
        event: CowrieLogEvent,
        binding_id: str,
        mapping: CowrieEventMapping,
        tags: list[str],
        command_rule_catalog: CowrieCommandRuleCatalog,
    ) -> tuple[list[TechniqueEvidence], ProfileSnapshot]:
        if not mapping.profile:
            return [], self._current_or_empty_profile(event.src_ip)

        evidences: list[TechniqueEvidence] = []
        profile = self._current_or_empty_profile(event.src_ip)
        for profile_tags, output in _profile_inputs(
            event,
            mapping,
            tags,
            command_rule_catalog,
        ):
            # Reuse the profiler's normalized event contract so Cowrie and
            # Falco-like telemetry can feed the same profile aggregation path.
            ingest_response = self._profiler_service.ingest(
                EvidenceIngestRequest(
                    attacker_key=event.src_ip,
                    binding_id=binding_id,
                    event=FalcoEvent(
                        ts=event.timestamp,
                        falco_rule=event.eventid,
                        priority=mapping.priority,
                        output=output,
                        tags=profile_tags,
                        output_fields=_output_fields(event, mapping),
                    ),
                )
            )
            evidences.extend(ingest_response.evidences)
            profile = ingest_response.profile
        return evidences, profile

    def _current_or_empty_profile(self, attacker_key: str) -> ProfileSnapshot:
        try:
            return self._profiler_service.get_profile(attacker_key)
        except ProfileNotFoundError:
            return ProfileSnapshot(attacker_key=attacker_key)


def _format_output(event: CowrieLogEvent, mapping: CowrieEventMapping) -> str:
    # output_template keeps human-readable profiler reasons data-driven.
    context = _event_context(event)
    try:
        return mapping.output_template.format(**context)
    except KeyError:
        # Bad or outdated templates should not drop telemetry ingestion.
        return f"{event.eventid} from {event.src_ip}"


def _output_fields(
    event: CowrieLogEvent,
    mapping: CowrieEventMapping,
) -> dict[str, object]:
    fields: dict[str, object] = {}
    # output_fields lets the catalog decide which Cowrie fields become profiler
    # source_ref fields for each event type.
    for field_name in mapping.output_fields:
        value = _event_value(event, field_name)
        if value is not None:
            fields[field_name] = value
    return fields


def _profile_inputs(
    event: CowrieLogEvent,
    mapping: CowrieEventMapping,
    base_tags: list[str],
    command_rule_catalog: CowrieCommandRuleCatalog,
) -> list[tuple[list[str], str]]:
    base_output = _format_output(event, mapping)
    profile_inputs = [(base_tags, base_output)]

    command = _event_value(event, mapping.command_field)
    if not isinstance(command, str):
        return profile_inputs

    for rule in command_rule_catalog.match(command):
        profile_inputs.append(
            (
                [rule.technique_id],
                f"{base_output} [{rule.name}; confidence={rule.confidence}]",
            )
        )
    return profile_inputs


def _event_context(event: CowrieLogEvent) -> dict[str, object]:
    # Template rendering needs safe defaults so missing optional Cowrie fields do
    # not produce noisy KeyError failures.
    context = {
        "source": "cowrie",
        "cowrie_eventid": event.eventid,
        "eventid": event.eventid,
        "src_ip": event.src_ip,
        "session": event.session or "",
        "sensor": event.sensor or "",
        "username": event.username or "<unknown>",
        "input": event.input or "",
        "message": event.message or "",
        "password_seen": event.password is not None,
    }
    if event.model_extra:
        # Cowrie event schemas differ by eventid; Pydantic keeps unknown JSON
        # keys in model_extra so mappings can reference them without model edits.
        context.update(event.model_extra)
    return context


def _event_value(event: CowrieLogEvent, field_name: str | None) -> object | None:
    # Field lookup supports first-class model fields, synthetic fields, and
    # event-specific extra JSON fields from Cowrie.
    if field_name is None:
        return None
    if field_name == "source":
        return "cowrie"
    if field_name == "cowrie_eventid":
        return event.eventid
    if field_name == "password_seen":
        return True if event.password is not None else None
    value = getattr(event, field_name, None)
    if value is not None:
        return value
    if event.model_extra:
        return event.model_extra.get(field_name)
    return None
