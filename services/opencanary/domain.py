"""Domain logic for ingesting OpenCanary multi-protocol telemetry."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from libs.common.clock import utcnow
from libs.common.iterables import dedupe_preserve
from libs.contracts.models import (
    EvidenceIngestRequest,
    FalcoEvent,
    OpenCanaryIngestRequest,
    OpenCanaryIngestResponse,
    OpenCanaryLogEvent,
    OpenCanaryObservation,
    ResolveBindingRequest,
)
from services.binding_service.domain import BindingService
from services.opencanary.repository import OpenCanaryObservationRepository
from services.profiler.domain import ProfilerService


_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "key",
    "pass",
    "password",
    "secret",
    "token",
}
_PORT_SERVICE_HINTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    443: "https",
    3306: "mysql",
    6379: "redis",
    9418: "git",
}
_SERVICE_CONTEXT_TAGS = {
    "ftp": ["mitre_lateral_movement", "T1021"],
    "git": ["mitre_collection", "T1213"],
    "smtp": ["mitre_discovery", "T1046"],
    "ssh": ["mitre_lateral_movement", "T1021"],
    "telnet": ["mitre_lateral_movement", "T1021"],
}


class OpenCanaryService:
    """Ingest OpenCanary logs into the binding/profile pipeline."""

    def __init__(
        self,
        binding_service: BindingService,
        profiler_service: ProfilerService,
        observation_repository: OpenCanaryObservationRepository,
    ) -> None:
        self._binding_service = binding_service
        self._profiler_service = profiler_service
        self._observation_repository = observation_repository

    def ingest(self, request: OpenCanaryIngestRequest) -> OpenCanaryIngestResponse:
        """Ingest one OpenCanary event and update binding/profile state."""
        event = request.event
        service = _service_name(event)
        safe_logdata = _redact_logdata(event.logdata)
        username = _username_from_logdata(event.logdata)
        password_seen = _password_seen(event.logdata)
        tags = _profile_tags(service=service, password_seen=password_seen, username=username)
        event_time = event.utc_time or utcnow()

        binding = self._binding_service.resolve(
            ResolveBindingRequest(
                attacker_key=event.src_host,
                protocol=request.protocol,
            )
        )
        ingest_response = self._profiler_service.ingest(
            EvidenceIngestRequest(
                attacker_key=event.src_host,
                binding_id=binding.binding_id,
                event=FalcoEvent(
                    ts=event_time,
                    falco_rule=f"OpenCanary {service} event",
                    priority="NOTICE" if password_seen or username else "INFO",
                    output=_format_output(event, service, username, password_seen),
                    tags=tags,
                    output_fields={
                        "source": "opencanary",
                        "opencanary_service": service,
                        "src_host": event.src_host,
                        "src_port": event.src_port,
                        "dst_host": event.dst_host,
                        "dst_port": event.dst_port,
                        "logtype": event.logtype,
                        "node_id": event.node_id,
                        "username": username,
                        "password_seen": password_seen,
                    },
                ),
            )
        )

        observation = OpenCanaryObservation(
            observation_id=str(uuid4()),
            ts=event_time,
            attacker_key=event.src_host,
            binding_id=binding.binding_id,
            service=service,
            src_host=event.src_host,
            src_port=event.src_port,
            dst_host=event.dst_host,
            dst_port=event.dst_port,
            logtype=event.logtype,
            node_id=event.node_id,
            username=username,
            password_seen=password_seen,
            logdata=safe_logdata,
            tags=tags,
            profiler_evidence_ids=[
                evidence.evidence_id for evidence in ingest_response.evidences
            ],
        )
        stored_observation = self._observation_repository.add(observation)
        return OpenCanaryIngestResponse(
            observation=stored_observation,
            binding=binding,
            profile=ingest_response.profile,
        )

def _service_name(event: OpenCanaryLogEvent) -> str:
    service = _case_insensitive_get(event.logdata, "SERVICE")
    if isinstance(service, str) and service.strip():
        return service.strip().lower()
    if event.dst_port in _PORT_SERVICE_HINTS:
        return _PORT_SERVICE_HINTS[int(event.dst_port)]
    return "unknown"


def _profile_tags(
    *,
    service: str,
    password_seen: bool,
    username: str | None,
) -> list[str]:
    base_tags = ["opencanary", f"opencanary_{service}"]
    behavior_tags: list[str]
    if password_seen or username:
        behavior_tags = ["mitre_credential_access", "T1110"]
    else:
        behavior_tags = ["mitre_discovery", "T1046"]
    return dedupe_preserve(
        [*behavior_tags, *_SERVICE_CONTEXT_TAGS.get(service, []), *base_tags]
    )


def _format_output(
    event: OpenCanaryLogEvent,
    service: str,
    username: str | None,
    password_seen: bool,
) -> str:
    target = event.dst_port if event.dst_port is not None else "unknown-port"
    parts = [f"OpenCanary {service} probe from {event.src_host} to {target}"]
    if username:
        parts.append(f"username={username}")
    if password_seen:
        parts.append("password_seen=true")
    return " ".join(parts)


def _username_from_logdata(logdata: dict[str, Any]) -> str | None:
    for key in ("USERNAME", "USER", "user", "username", "login"):
        value = _case_insensitive_get(logdata, key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _password_seen(logdata: dict[str, Any]) -> bool:
    for key, value in logdata.items():
        if _is_sensitive_key(key) and value not in (None, "", [], {}):
            return True
    return False


def _redact_logdata(logdata: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in logdata.items():
        safe[key] = "[redacted]" if _is_sensitive_key(key) else value
    return safe


def _case_insensitive_get(logdata: dict[str, Any], name: str) -> Any:
    lowered = name.lower()
    for key, value in logdata.items():
        if key.lower() == lowered:
            return value
    return None


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SENSITIVE_KEYS)
