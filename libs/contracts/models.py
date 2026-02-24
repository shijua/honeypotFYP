from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from libs.common.clock import utcnow


class VersionedModel(BaseModel):
    # All cross-service payloads carry a schema version for future evolution.
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "v1"


# ---- Binding / routing lifecycle contracts ----
class BindingStatus(str, Enum):
    active = "active"
    idle = "idle"
    recycled = "recycled"
    recovered = "recovered"


class DecisionType(str, Enum):
    bind = "bind"
    unlock = "unlock"
    route_update = "route_update"
    recycle = "recycle"
    noop = "noop"


class ActionType(str, Enum):
    bind = "bind"
    unlock = "unlock"
    recycle = "recycle"
    route_update = "route_update"
    noop = "noop"


class ResolveBindingRequest(VersionedModel):
    attacker_key: str = Field(min_length=1)
    protocol: str = Field(default="tcp", min_length=1)


class RouteRequest(VersionedModel):
    attacker_key: str = Field(min_length=1)
    protocol: str = Field(default="tcp", min_length=1)


class HeartbeatRequest(VersionedModel):
    ts: datetime = Field(default_factory=utcnow)


class RecycleRequest(VersionedModel):
    mode: Literal["idle", "hard"] = "idle"


class BindingRecord(VersionedModel):
    binding_id: str
    attacker_key: str
    backend_instance_id: str
    status: BindingStatus
    first_seen_ts: datetime
    last_seen_ts: datetime
    ttl_expires_at: datetime
    volume_ref: str | None = None
    unlocked_assets: list[str] = Field(default_factory=list)


class RouteResponse(VersionedModel):
    binding_id: str
    backend_instance_id: str
    status: BindingStatus


# ---- Evidence and profiling contracts ----
class FalcoEvent(VersionedModel):
    ts: datetime
    falco_rule: str
    priority: str
    output: str
    hostname: str | None = None
    tags: list[str] = Field(default_factory=list)
    output_fields: dict[str, Any] = Field(default_factory=dict)


class TechniqueEvidence(VersionedModel):
    evidence_id: str
    ts: datetime
    attacker_key: str
    binding_id: str
    tech_id: str
    group: str
    weight: float
    success: bool
    reason: str
    source_ref: dict[str, Any] = Field(default_factory=dict)


class ProfileSnapshot(VersionedModel):
    attacker_key: str
    conf_by_tactic: dict[str, float] = Field(default_factory=dict)
    conf_by_technique: dict[str, float] = Field(default_factory=dict)
    level_by_tactic: dict[str, int] = Field(default_factory=dict)
    level_by_technique: dict[str, int] = Field(default_factory=dict)
    recent_tactics: list[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=utcnow)


# ---- Controller decision contracts ----
class AssetDefinition(VersionedModel):
    asset_id: str
    asset_name: str
    exposure_type: Literal["public", "internal"]
    interaction_level: Literal["low", "medium", "high"]
    covers_tactics: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)


class ControllerTickRequest(VersionedModel):
    attacker_key: str
    binding_id: str
    profile: ProfileSnapshot
    assets: list[AssetDefinition] = Field(default_factory=list)
    unlocked_asset_ids: list[str] = Field(default_factory=list)


class ControllerAction(VersionedModel):
    action_type: ActionType
    binding_id: str
    asset_id: str | None = None
    reason: str


class DecisionEvent(VersionedModel):
    ts: datetime = Field(default_factory=utcnow)
    attacker_key: str
    binding_id: str
    decision_type: DecisionType
    reason: str
    trigger_evidence_ids: list[str] = Field(default_factory=list)
    asset_added: str | None = None
    asset_removed: str | None = None


# ---- Attack-graph probability contracts ----
class EdgeStats(VersionedModel):
    edge_id: str
    n_avail: int = 0
    n_taken: int = 0
    alpha: float = 1.0
    beta: float = 1.0
    mean_probability: float = 0.5
    updated_at: datetime = Field(default_factory=utcnow)


class EdgeObservationRequest(VersionedModel):
    edge_id: str
    binding_id: str
