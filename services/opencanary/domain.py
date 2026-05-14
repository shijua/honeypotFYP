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
_LOGIN_LOGTYPES = {2000, 4002, 6001, 8001, 9001, 9002}
_LATERAL_LOGIN_SERVICES = {"ftp", "ssh", "telnet"}
_REDIS_COLLECTION_COMMANDS = {
    "GET",
    "HGET",
    "HGETALL",
    "KEYS",
    "LRANGE",
    "MGET",
    "SCAN",
    "SMEMBERS",
}
_REDIS_CREDENTIAL_COMMANDS = {"AUTH", "CONFIG"}
_SMTP_CREDENTIAL_COMMANDS = {"AUTH"}
_SMTP_DISCOVERY_COMMANDS = {"EHLO", "EXPN", "HELO", "MAIL", "RCPT", "VRFY"}


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
        login_probe = _is_login_probe(
            event=event,
            service=service,
            password_seen=password_seen,
            username=username,
        )
        tags = _profile_tags(
            event=event,
            service=service,
            password_seen=password_seen,
            username=username,
        )
        event_time = event.utc_time or utcnow()
        profile_context = _profile_context(event.logdata)

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
                    priority="NOTICE" if login_probe else "INFO",
                    output=_format_output(event, service, username, password_seen),
                    tags=tags,
                    output_fields={
                        "source": "opencanary",
                        "opencanary_service": service,
                        "opencanary_logtype": event.logtype,
                        "src_ip": event.src_host,
                        "src_host": event.src_host,
                        "src_port": event.src_port,
                        "dest_ip": event.dst_host,
                        "dst_host": event.dst_host,
                        "dest_port": event.dst_port,
                        "dst_port": event.dst_port,
                        "logtype": event.logtype,
                        "node_id": event.node_id,
                        "username": username,
                        "password_seen": password_seen,
                        **profile_context,
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
    """Resolve a stable service name from OpenCanary logdata or destination port.

    Example:
        logdata={"SERVICE": "redis"} -> "redis"
        dst_port=3306 -> "mysql"
    """
    service = _case_insensitive_get(event.logdata, "SERVICE")
    if isinstance(service, str) and service.strip():
        return service.strip().lower()
    if event.dst_port in _PORT_SERVICE_HINTS:
        return _PORT_SERVICE_HINTS[int(event.dst_port)]
    return "unknown"


def _profile_tags(
    *,
    event: OpenCanaryLogEvent,
    service: str,
    password_seen: bool,
    username: str | None,
) -> list[str]:
    """Map one OpenCanary event into profiler ATT&CK tags.

    Example:
        redis COMMAND=KEYS -> ["mitre_discovery", "T1046", "mitre_collection", "T1213", ...]
        ftp USER/PASS -> ["mitre_credential_access", "T1110", "mitre_lateral_movement", "T1021", ...]
    """
    base_tags = ["opencanary", f"opencanary_{service}"]
    if _is_login_probe(
        event=event,
        service=service,
        password_seen=password_seen,
        username=username,
    ):
        behavior_tags = ["mitre_credential_access", "T1110"]
        if service in _LATERAL_LOGIN_SERVICES:
            behavior_tags.extend(["mitre_lateral_movement", "T1021"])
        return dedupe_preserve([*behavior_tags, *base_tags])
    if service == "git":
        return dedupe_preserve([
            "mitre_discovery",
            "T1046",
            "mitre_collection",
            "T1213",
            *base_tags,
        ])
    if service == "redis":
        return dedupe_preserve([*_redis_tags(event.logdata), *base_tags])
    if service == "smtp":
        return dedupe_preserve([*_smtp_tags(event.logdata), *base_tags])
    return dedupe_preserve(["mitre_discovery", "T1046", *base_tags])


def _is_login_probe(
    *,
    event: OpenCanaryLogEvent,
    service: str,
    password_seen: bool,
    username: str | None,
) -> bool:
    """Return whether an OpenCanary event represents a login or auth attempt.

    Example:
        logtype=8001 for MySQL login -> True
        smtp COMMANDS=["EHLO", "AUTH"] -> True
    """
    if password_seen or username:
        return True
    if event.logtype in _LOGIN_LOGTYPES:
        return True
    if service == "smtp" and _has_any_command(
        event.logdata,
        _SMTP_CREDENTIAL_COMMANDS,
    ):
        return True
    return False


def _redis_tags(logdata: dict[str, Any]) -> list[str]:
    """Map Redis command probes to low-noise ATT&CK tags.

    Example:
        COMMAND=INFO -> Discovery/T1046
        COMMAND=KEYS -> Discovery/T1046 plus Collection/T1213
    """
    command = _command_from_logdata(logdata)
    if command in _REDIS_CREDENTIAL_COMMANDS:
        return ["mitre_discovery", "T1046", "mitre_credential_access", "T1552.001"]
    if command in _REDIS_COLLECTION_COMMANDS:
        return ["mitre_discovery", "T1046", "mitre_collection", "T1213"]
    return ["mitre_discovery", "T1046"]


def _smtp_tags(logdata: dict[str, Any]) -> list[str]:
    """Map SMTP command probes to low-noise ATT&CK tags.

    Example:
        COMMANDS=["VRFY"] -> Discovery/T1046
        COMMANDS=["AUTH"] -> Credential Access/T1110
    """
    tags: list[str] = []
    if _has_any_command(logdata, _SMTP_CREDENTIAL_COMMANDS):
        tags.extend(["mitre_credential_access", "T1110"])
    if not tags or _has_any_command(logdata, _SMTP_DISCOVERY_COMMANDS):
        tags.extend(["mitre_discovery", "T1046"])
    return tags


def _format_output(
    event: OpenCanaryLogEvent,
    service: str,
    username: str | None,
    password_seen: bool,
) -> str:
    """Format a concise profiler reason string for one OpenCanary event.

    Example:
        service="git", REPO="infra-deploy.git" -> "OpenCanary git probe ... repo=infra-deploy.git"
    """
    target = event.dst_port if event.dst_port is not None else "unknown-port"
    parts = [f"OpenCanary {service} probe from {event.src_host} to {target}"]
    if username:
        parts.append(f"username={username}")
    if password_seen:
        parts.append("password_seen=true")
    command = _command_from_logdata(event.logdata)
    if command:
        parts.append(f"command={command}")
    repo = _text_from_logdata(event.logdata, "REPO", "REPOSITORY")
    if repo:
        parts.append(f"repo={repo}")
    return " ".join(parts)


def _username_from_logdata(logdata: dict[str, Any]) -> str | None:
    """Extract a username from common OpenCanary logdata keys.

    Example:
        {"USERNAME": "root"} -> "root"
    """
    for key in ("USERNAME", "USER", "user", "username", "login"):
        value = _case_insensitive_get(logdata, key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _password_seen(logdata: dict[str, Any]) -> bool:
    """Return whether credential-like material was present without exposing it.

    Example:
        {"PASSWORD": "letmein"} -> True
    """
    for key, value in logdata.items():
        if _is_sensitive_key(key) and value not in (None, "", [], {}):
            return True
    return False


def _redact_logdata(logdata: dict[str, Any]) -> dict[str, Any]:
    """Return logdata with secret-like fields replaced by a redaction marker.

    Example:
        {"PASSWORD": "letmein", "USERNAME": "root"} -> {"PASSWORD": "[redacted]", "USERNAME": "root"}
    """
    safe: dict[str, Any] = {}
    for key, value in logdata.items():
        safe[key] = "[redacted]" if _is_sensitive_key(key) else value
    return safe


def _profile_context(logdata: dict[str, Any]) -> dict[str, Any]:
    """Keep non-secret protocol details so dashboard evidence is explainable.

    Example:
        {"COMMANDS": ["EHLO", "AUTH"], "REPO": "infra.git"} -> {"opencanary_commands": ["EHLO", "AUTH"], "opencanary_repo": "infra.git"}
    """
    context: dict[str, Any] = {}
    command = _command_from_logdata(logdata)
    commands = _commands_from_logdata(logdata)
    repo = _text_from_logdata(logdata, "REPO", "REPOSITORY")
    if command:
        context["opencanary_command"] = command
    if commands:
        context["opencanary_commands"] = commands
    if repo:
        context["opencanary_repo"] = repo
    return context


def _command_from_logdata(logdata: dict[str, Any]) -> str | None:
    """Extract the first protocol command as an uppercase verb.

    Example:
        {"COMMAND": "keys *"} -> "KEYS"
        {"COMMANDS": ["EHLO tester"]} -> "EHLO"
    """
    value = _case_insensitive_get(logdata, "COMMAND")
    if value is None:
        value = _case_insensitive_get(logdata, "CMD")
    if isinstance(value, str) and value.strip():
        return value.strip().split()[0].upper()
    if isinstance(value, list) and value:
        first = value[0]
        if isinstance(first, str) and first.strip():
            return first.strip().split()[0].upper()
    return None


def _commands_from_logdata(logdata: dict[str, Any]) -> list[str]:
    """Extract all command verbs from OpenCanary-style command fields.

    Example:
        {"COMMANDS": ["EHLO tester", "AUTH LOGIN"]} -> ["EHLO", "AUTH"]
    """
    commands: list[str] = []
    value = _case_insensitive_get(logdata, "COMMANDS")
    if isinstance(value, list):
        commands.extend(
            item.strip().split()[0].upper()
            for item in value
            if isinstance(item, str) and item.strip()
        )
    single = _command_from_logdata(logdata)
    if single:
        commands.append(single)
    return dedupe_preserve(commands)


def _has_any_command(logdata: dict[str, Any], commands: set[str]) -> bool:
    """Return whether any extracted command belongs to a target set.

    Example:
        _has_any_command({"COMMANDS": ["AUTH LOGIN"]}, {"AUTH"}) -> True
    """
    return any(command in commands for command in _commands_from_logdata(logdata))


def _text_from_logdata(logdata: dict[str, Any], *names: str) -> str | None:
    """Return the first non-empty text value for any candidate key name.

    Example:
        _text_from_logdata({"REPO": "infra.git"}, "REPO", "REPOSITORY") -> "infra.git"
    """
    for name in names:
        value = _case_insensitive_get(logdata, name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _case_insensitive_get(logdata: dict[str, Any], name: str) -> Any:
    """Fetch a logdata value regardless of key casing.

    Example:
        _case_insensitive_get({"Service": "redis"}, "SERVICE") -> "redis"
    """
    lowered = name.lower()
    for key, value in logdata.items():
        if key.lower() == lowered:
            return value
    return None


def _is_sensitive_key(key: str) -> bool:
    """Return whether a field name looks secret-bearing and should be redacted.

    Example:
        "PASSWORD" -> True
        "USERNAME" -> False
    """
    lowered = key.lower()
    return any(marker in lowered for marker in _SENSITIVE_KEYS)
