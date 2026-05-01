"""Shared request, response, and persistence models for the honeynet MVP.

All services exchange these Pydantic models instead of defining local schemas.
That keeps API payloads, stored state, and tests aligned around one contract.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from libs.common.clock import utcnow


class VersionedModel(BaseModel):
    """Base class for shared payloads that carry a schema version.

    Example:
        {"schema_version": "v1", ...}
    """

    # Carry a schema version on every shared payload.
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "v1"


# ---- Binding / routing lifecycle contracts ----
class BindingStatus(str, Enum):
    """Lifecycle state for one attacker binding.

    Example value:
        "active"
    """

    active = "active"
    idle = "idle"
    recycled = "recycled"
    recovered = "recovered"


class DecisionType(str, Enum):
    """Audit event type emitted by controller/orchestrator logic.

    Example value:
        "unlock"
    """

    bind = "bind"
    unlock = "unlock"
    route_update = "route_update"
    recycle = "recycle"
    noop = "noop"


class ActionType(str, Enum):
    """Concrete action that one service asks another service to apply.

    Example value:
        "route_update"
    """

    bind = "bind"
    unlock = "unlock"
    recycle = "recycle"
    route_update = "route_update"
    noop = "noop"


class ResolveBindingRequest(VersionedModel):
    """Request to resolve an attacker into a sticky binding.

    Example:
        {"attacker_key": "198.51.100.10", "protocol": "tcp"}
    """

    attacker_key: str = Field(min_length=1)
    protocol: str = Field(default="tcp", min_length=1)


class RouteRequest(VersionedModel):
    """Request to look up routing for one attacker/protocol pair.

    Example:
        {"attacker_key": "198.51.100.10", "protocol": "tcp"}
    """

    attacker_key: str = Field(min_length=1)
    protocol: str = Field(default="tcp", min_length=1)


class HeartbeatRequest(VersionedModel):
    """Request to refresh liveness for an existing binding.

    Example:
        {"ts": "2026-04-18T12:00:00Z"}
    """

    ts: datetime = Field(default_factory=utcnow)


class RecycleRequest(VersionedModel):
    """Request to recycle one binding in idle or hard mode.

    Example:
        {"mode": "idle"}
    """

    mode: Literal["idle", "hard"] = "idle"


class BindingRecord(VersionedModel):
    """Persisted binding state for one attacker/backend pairing.

    Example:
        {"binding_id": "binding-1", "attacker_key": "198.51.100.10", "unlocked_assets": ["git-internal"]}
    """

    binding_id: str
    attacker_key: str
    backend_instance_id: str
    status: BindingStatus
    first_seen_ts: datetime
    last_seen_ts: datetime
    ttl_expires_at: datetime
    volume_ref: Optional[str] = None
    # Track assets revealed for this binding.
    unlocked_assets: List[str] = Field(default_factory=list)


class RouteResponse(VersionedModel):
    """Minimal routing answer returned by a route lookup.

    Example:
        {"binding_id": "binding-1", "backend_instance_id": "ns-1234abcd", "status": "active"}
    """

    binding_id: str
    backend_instance_id: str
    status: BindingStatus


# ---- Evidence and profiling contracts ----
class FalcoEvent(VersionedModel):
    """Normalized security event ingested by the profiler.

    Example:
        {"falco_rule": "Read sensitive file", "tags": ["mitre_credential_access", "T1003"]}
    """

    ts: datetime
    falco_rule: str
    priority: str
    output: str
    hostname: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    output_fields: Dict[str, Any] = Field(default_factory=dict)


class TechniqueEvidence(VersionedModel):
    """Profiler evidence derived from one event and optionally mapped to ATT&CK.

    One incoming observation can produce one or more evidence records. For
    example, a single public HTTP request may map to both Initial Access and
    Discovery if it matches multiple rule tags. Evidence is the durable link
    between raw adapter events, profile aggregation, and later controller
    decisions.

    Field meaning:
    - evidence_id: unique id used by decision traces and adaptive-loop de-duping
    - ts: event timestamp normalized by the producing adapter/profiler
    - attacker_key: source identity used for binding and routing, usually source IP
    - binding_id: active binding/session that this evidence belongs to
    - tech_id: optional ATT&CK technique or sub-technique id, such as T1552.001
    - group: optional ATT&CK tactic name, such as Credential Access
    - weight: confidence contribution used when rebuilding ProfileSnapshot
    - success: best-effort success flag; probes are usually true unless clearly failed
    - reason: short human-readable explanation for dashboards and traces
    - source_ref: compact original context, such as public HTTP path/rules,
      Cowrie command fields, OpenCanary service fields, or Falco output fields

    Example:
        {
            "tech_id": "T1552.001",
            "group": "Credential Access",
            "weight": 2.5,
            "source_ref": {
                "source": "public_http",
                "http_path": "/.env.old",
                "http_rule_names": ["public_http_credential_discovery"],
                "http_indicators": ["combined:.env", "path:.old"]
            }
        }
    """

    evidence_id: str
    ts: datetime
    attacker_key: str
    binding_id: str
    tech_id: Optional[str] = None
    group: Optional[str] = None
    weight: float
    success: bool
    reason: str
    source_ref: Dict[str, Any] = Field(default_factory=dict)


class ProfileSnapshot(VersionedModel):
    """Current aggregated attacker profile built by the profiler.

    This snapshot is the controller's main input for deciding which asset to
    expose next. It contains both ATT&CK-level behavioural confidence and the
    concrete public-surface breadcrumbs that were recently touched. The latter
    is what lets the controller enforce file-exploration dependencies such as
    "only consider finance-share after a backup file was requested".

    Field meaning:
    - conf_by_tactic: confidence score per ATT&CK tactic in the range [0, 1]
    - conf_by_technique: confidence score per ATT&CK technique in the range [0, 1]
    - level_by_tactic: coarse repetition level per tactic, usually 1/2/3
    - level_by_technique: coarse repetition level per technique, usually 1/2/3
    - recent_tactics: de-duplicated recent tactic chain within the short time window
    - recent_techniques: de-duplicated recent technique chain within the short time window
    - recent_evidence_ids: the most recent evidence ids used to explain decisions
    - recent_public_http_paths: suspicious public web paths observed in the short window
    - recent_public_http_rules: local public HTTP rule names that matched those paths
    - recent_public_http_indicators: concrete matched tokens such as path:.bak or combined:.env
    - updated_at: timestamp of the newest evidence included in this snapshot

    Example:
        {
            "attacker_key": "198.51.100.10",
            "conf_by_tactic": {"Credential Access": 0.82, "Discovery": 0.41},
            "conf_by_technique": {"T1003": 0.82},
            "level_by_tactic": {"Credential Access": 2, "Discovery": 1},
            "level_by_technique": {"T1003": 2},
            "recent_tactics": ["Discovery", "Credential Access"],
            "recent_techniques": ["T1003"],
            "recent_evidence_ids": ["e-1", "e-2"],
            "recent_public_http_paths": ["/.env.old"],
            "recent_public_http_rules": ["public_http_credential_discovery"],
            "recent_public_http_indicators": ["combined:.env", "path:.old"],
            "updated_at": "2026-04-18T12:00:00Z"
        }
    """

    attacker_key: str
    conf_by_tactic: Dict[str, float] = Field(default_factory=dict)
    conf_by_technique: Dict[str, float] = Field(default_factory=dict)
    level_by_tactic: Dict[str, int] = Field(default_factory=dict)
    level_by_technique: Dict[str, int] = Field(default_factory=dict)
    # Keep a short-term view for controller decisions.
    recent_tactics: List[str] = Field(default_factory=list)
    recent_techniques: List[str] = Field(default_factory=list)
    recent_evidence_ids: List[str] = Field(default_factory=list)
    recent_public_http_paths: List[str] = Field(default_factory=list)
    recent_public_http_rules: List[str] = Field(default_factory=list)
    recent_public_http_indicators: List[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=utcnow)


class EvidenceIngestRequest(VersionedModel):
    """Request to send one Falco event through the profiler.

    Example:
        {"attacker_key": "198.51.100.10", "binding_id": "binding-1", "event": {...}}
    """

    attacker_key: str = Field(min_length=1)
    binding_id: str = Field(min_length=1)
    event: FalcoEvent


class EvidenceIngestResponse(VersionedModel):
    """Profiler response containing new evidence and the refreshed profile.

    Example:
        {"evidences": [{...}], "profile": {...}}
    """

    attacker_key: str
    binding_id: str
    evidences: List[TechniqueEvidence] = Field(default_factory=list)
    profile: ProfileSnapshot


# ---- Controller decision contracts ----
class AssetDefinition(VersionedModel):
    """One candidate honeypot asset that the controller may expose.

    `dependencies` names assets that must already be unlocked. Assets may also
    put `unlock_signals` inside `default_settings` to require recent profile
    evidence before they become eligible. Supported signal keys are
    `any_http_paths`, `any_http_rules`, and `any_http_indicators`; each matches
    against the corresponding `ProfileSnapshot.recent_public_http_*` field.
    Optional `default_settings.selection_profile` metadata describes reveal
    outputs and tactic difficulty for future controller scoring without adding
    new top-level contract fields.

    Example:
        {
            "asset_id": "finance-share",
            "template_family": "file-share-honeypot",
            "protocols": ["http"],
            "ports": [80],
            "dependencies": ["internal-portal"],
            "default_settings": {
                "unlock_signals": {
                    "any_http_paths": ["/backup/db_backup_2024.sql.bak"],
                    "any_http_indicators": ["path:.bak"]
                },
                "selection_profile": {
                    "tactic_difficulties": {"Collection": 2},
                    "reveal_outputs": ["finance exports"]
                }
            },
            "covers_tactics": ["Credential Access", "Collection"]
        }
    """

    asset_id: str
    asset_name: str
    exposure_type: Literal["public", "internal"]
    interaction_level: Literal["low", "medium", "high"]
    description: Optional[str] = None
    template_family: Optional[str] = None
    protocols: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    source_refs: List[str] = Field(default_factory=list)
    telemetry_source: Optional[str] = None
    default_settings: Dict[str, Any] = Field(default_factory=dict)
    covers_tactics: List[str] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)


class ControllerTickRequest(VersionedModel):
    """Input sent to the controller for one decision tick.

    The controller combines `unlocked_asset_ids` with the supplied profile. An
    asset is eligible only when its asset dependencies are already unlocked and
    its optional profile-level unlock signals are present.

    Example:
        {
            "binding_id": "binding-1",
            "profile": {
                "recent_public_http_paths": ["/backup/db_backup_2024.sql.bak"]
            },
            "unlocked_asset_ids": ["internal-portal"]
        }
    """

    attacker_key: str
    binding_id: str
    profile: ProfileSnapshot
    # Tests may inject assets directly instead of using the catalog.
    assets: List[AssetDefinition] = Field(default_factory=list)
    unlocked_asset_ids: List[str] = Field(default_factory=list)


class ControllerAction(VersionedModel):
    """One action proposed by the controller.

    Example:
        {"action_type": "unlock", "binding_id": "binding-1", "asset_id": "git-internal"}
    """

    action_type: ActionType
    binding_id: str
    asset_id: Optional[str] = None
    reason: str


class DecisionEvent(VersionedModel):
    """Explainable audit record for one controller or orchestrator decision.

    Example:
        {"decision_type": "unlock", "asset_added": "git-internal", "trigger_evidence_ids": ["e-1"]}
    """

    ts: datetime = Field(default_factory=utcnow)
    attacker_key: str
    binding_id: str
    decision_type: DecisionType
    reason: str
    trigger_evidence_ids: List[str] = Field(default_factory=list)
    asset_added: Optional[str] = None
    asset_removed: Optional[str] = None


class ControllerTickResponse(VersionedModel):
    """Controller output for one tick.

    Example:
        {"actions": [{...}], "decision_events": [{...}], "candidate_asset_ids": ["git-internal"]}
    """

    binding_id: str
    actions: List[ControllerAction] = Field(default_factory=list)
    decision_events: List[DecisionEvent] = Field(default_factory=list)
    # Expose which assets were considered on this tick.
    candidate_asset_ids: List[str] = Field(default_factory=list)


class OrchestratorApplyRequest(VersionedModel):
    """Request to apply controller actions to the current binding state.

    Example:
        {"binding_id": "binding-1", "actions": [{...}]}
    """

    binding_id: str = Field(min_length=1)
    actions: List[ControllerAction] = Field(default_factory=list)


class OrchestratorApplyResponse(VersionedModel):
    """Result of applying controller actions.

    Example:
        {"binding": {...}, "route_updates": ["binding binding-1 exposes git-internal"]}
    """

    binding: BindingRecord
    applied_actions: List[ControllerAction] = Field(default_factory=list)
    route_updates: List[str] = Field(default_factory=list)
    runtime_events: List["AssetRuntimeRecord"] = Field(default_factory=list)
    monitoring_events: List[FalcoEvent] = Field(default_factory=list)


class AssetRuntimeRecord(VersionedModel):
    """Mock runtime state produced when the orchestrator enables one asset.

    This is the MVP stand-in for a future Docker/Kubernetes object. It records
    the concrete settings that would be used to launch the decoy template.

    Example:
        {
            "binding_id": "binding-1",
            "asset_id": "admin-jumpbox",
            "status": "running",
            "settings": {"banner": "OpenSSH_8.2"}
        }
    """

    runtime_id: str
    binding_id: str
    asset_id: str
    asset_name: str
    template_family: Optional[str] = None
    status: Literal["running", "stopped", "failed"] = "running"
    protocols: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_refs: List[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utcnow)


class GatewayBindingState(VersionedModel):
    """Gateway-facing view of what one binding currently exposes.

    Example:
        {"binding_id": "binding-1", "exposed_assets": ["git-internal"], "route_updates": ["..."]}
    """

    binding_id: str
    attacker_key: str
    backend_instance_id: str
    status: BindingStatus
    exposed_assets: List[str] = Field(default_factory=list)
    failed_assets: List[str] = Field(default_factory=list)
    route_updates: List[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=utcnow)


class GatewaySyncRequest(VersionedModel):
    """Request used to sync the latest binding state into the gateway view.

    Example:
        {"binding": {...}, "route_updates": ["binding binding-1 exposes git-internal"]}
    """

    binding: BindingRecord
    route_updates: List[str] = Field(default_factory=list)
    # Optional override used when "unlocked" and "currently reachable" differ.
    exposed_assets_override: Optional[List[str]] = None
    failed_assets_override: Optional[List[str]] = None


class GatewaySyncResponse(VersionedModel):
    """Gateway response after route state has been synced.

    Example:
        {"state": {...GatewayBindingState...}}
    """

    state: GatewayBindingState


# ---- Public entrypoint capture contracts ----
class EntrypointCaptureRequest(VersionedModel):
    """Normalized HTTP request captured by the low-interaction web honeypot.

    Example:
        {
            "attacker_key": "198.51.100.10",
            "method": "POST",
            "path": "/wp-login.php",
            "query_string": "redirect_to=/wp-admin",
            "headers": {"user-agent": "curl/8.0"},
            "body_preview": "log=admin&pwd=[redacted]"
        }
    """

    attacker_key: str = Field(min_length=1)
    method: str = Field(min_length=1)
    path: str = Field(min_length=1)
    query_string: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    body_preview: Optional[str] = None
    body_truncated: bool = False
    protocol: str = Field(default="tcp", min_length=1)


class EntrypointObservation(VersionedModel):
    """Persisted observation from one public honeypot request.

    Rule metadata is stored with the observation so the dashboard can show the
    concrete evidence, such as `user_agent:sqlmap`, behind a MITRE tag.

    Example:
        {
            "observation_id": "obs-1",
            "attacker_key": "198.51.100.10",
            "binding_id": "binding-1",
            "method": "GET",
            "path": "/.env",
            "status_code": 404,
            "matched_rules": ["public_http_credential_discovery"],
            "tags": ["mitre_credential_access", "T1552.001"],
            "indicators": ["combined:.env"]
        }
    """

    observation_id: str
    ts: datetime
    attacker_key: str
    binding_id: str
    method: str
    path: str
    query_string: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    body_preview: Optional[str] = None
    body_truncated: bool = False
    user_agent: Optional[str] = None
    status_code: int = 404
    matched_rules: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)
    profiler_evidence_ids: List[str] = Field(default_factory=list)


class EntrypointCaptureResponse(VersionedModel):
    """Internal result after an entrypoint request has been captured.

    Example:
        {"observation": {...}, "binding": {...}, "profile": {...}}
    """

    observation: EntrypointObservation
    binding: BindingRecord
    profile: ProfileSnapshot


# ---- Cowrie SSH honeypot telemetry contracts ----
class CowrieLogEvent(VersionedModel):
    """Raw-ish Cowrie JSON event accepted by the Cowrie adapter.

    Cowrie event schemas vary by `eventid`, so this model allows extra fields
    while still naming the fields the MVP adapter understands.

    Example:
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-04-20T12:00:00Z",
            "src_ip": "198.51.100.10",
            "session": "s-1",
            "input": "uname -a"
        }
    """

    model_config = ConfigDict(extra="allow")

    eventid: str = Field(min_length=1)
    timestamp: datetime
    src_ip: str = Field(min_length=1)
    session: Optional[str] = None
    sensor: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    input: Optional[str] = None
    message: Optional[str] = None


class CowrieObservation(VersionedModel):
    """Persisted sanitized observation from one Cowrie log event.

    Example:
        {
            "observation_id": "obs-1",
            "eventid": "cowrie.login.failed",
            "attacker_key": "198.51.100.10",
            "binding_id": "binding-1",
            "username": "root",
            "password_seen": true
        }
    """

    observation_id: str
    ts: datetime
    attacker_key: str
    binding_id: str
    eventid: str
    session: Optional[str] = None
    sensor: Optional[str] = None
    username: Optional[str] = None
    password_seen: bool = False
    command: Optional[str] = None
    message: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    profiler_evidence_ids: List[str] = Field(default_factory=list)


class CowrieIngestRequest(VersionedModel):
    """Request to ingest one Cowrie JSON event.

    Example:
        {"event": {...CowrieLogEvent...}, "protocol": "ssh"}
    """

    event: CowrieLogEvent
    protocol: str = Field(default="ssh", min_length=1)


class CowrieIngestResponse(VersionedModel):
    """Result after Cowrie telemetry has updated binding/profile state.

    Example:
        {"observation": {...}, "binding": {...}, "profile": {...}}
    """

    observation: CowrieObservation
    binding: BindingRecord
    profile: ProfileSnapshot


# ---- OpenCanary multi-protocol entrypoint telemetry contracts ----
class OpenCanaryLogEvent(VersionedModel):
    """Raw-ish OpenCanary JSON event accepted by the OpenCanary adapter.

    OpenCanary log schemas vary by emulated service, so this model keeps common
    fields named while allowing service-specific extras.
    """

    model_config = ConfigDict(extra="allow")

    src_host: str = Field(min_length=1)
    src_port: Optional[int] = None
    dst_host: Optional[str] = None
    dst_port: Optional[int] = None
    local_time: Optional[str] = None
    local_time_adjusted: Optional[str] = None
    utc_time: Optional[datetime] = None
    logtype: Optional[int] = None
    node_id: Optional[str] = None
    logdata: Dict[str, Any] = Field(default_factory=dict)


class OpenCanaryObservation(VersionedModel):
    """Persisted sanitized observation from one OpenCanary log event."""

    observation_id: str
    ts: datetime
    attacker_key: str
    binding_id: str
    service: str
    src_host: str
    src_port: Optional[int] = None
    dst_host: Optional[str] = None
    dst_port: Optional[int] = None
    logtype: Optional[int] = None
    node_id: Optional[str] = None
    username: Optional[str] = None
    password_seen: bool = False
    logdata: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    profiler_evidence_ids: List[str] = Field(default_factory=list)


class OpenCanaryIngestRequest(VersionedModel):
    """Request to ingest one OpenCanary JSON event."""

    event: OpenCanaryLogEvent
    protocol: str = Field(default="tcp", min_length=1)


class OpenCanaryIngestResponse(VersionedModel):
    """Result after OpenCanary telemetry has updated binding/profile state."""

    observation: OpenCanaryObservation
    binding: BindingRecord
    profile: ProfileSnapshot


# TODO edge with from and to
# ---- Attack-graph probability contracts ----
class EdgeStats(VersionedModel):
    """Lightweight probability statistics for one attack-graph edge.

    Example:
        {"edge_id": "cred->collect", "alpha": 2.0, "beta": 1.0, "mean_probability": 0.66}
    """

    edge_id: str
    n_avail: int = 0
    n_taken: int = 0
    alpha: float = 1.0
    beta: float = 1.0
    mean_probability: float = 0.5
    updated_at: datetime = Field(default_factory=utcnow)


class EdgeObservationRequest(VersionedModel):
    """Observation request for updating one attack-graph edge.

    Example:
        {"edge_id": "cred->collect", "binding_id": "binding-1"}
    """

    edge_id: str
    binding_id: str
