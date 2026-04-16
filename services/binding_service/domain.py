from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from libs.common.clock import utcnow
from libs.contracts.models import (
    BindingRecord,
    BindingStatus,
    HeartbeatRequest,
    RecycleRequest,
    ResolveBindingRequest,
)
from services.binding_service.repository import BindingRepository


class BindingNotFoundError(KeyError):
    """Raised when a binding_id does not exist in the repository."""

    pass


class BindingService:
    """Core lifecycle service for attacker-to-backend bindings.

    Responsibilities:
    - Resolve sticky bindings for attacker_key.
    - Refresh liveness/TTL via heartbeat.
    - Recycle bindings with idle/hard semantics.
    """

    def __init__(
        self,
        repository: BindingRepository,
        ttl_seconds: int = 7 * 24 * 60 * 60,
    ) -> None:
        self._repository = repository
        self._ttl = timedelta(seconds=ttl_seconds)

    def resolve(self, request: ResolveBindingRequest) -> BindingRecord:
        """Resolve or create a binding for an attacker.

        Behavior:
        - If an unexpired binding exists, reuse it (sticky behavior).
        - If that reused binding was recycled, mark it as recovered.
        - Otherwise create a fresh binding record.
        """
        now = utcnow()
        existing = self._repository.get_by_attacker(request.attacker_key)
        if existing and existing.ttl_expires_at >= now:
            # Recycled bindings are resumed as recovered to preserve attacker state.
            status = (
                BindingStatus.recovered
                if existing.status == BindingStatus.recycled
                else BindingStatus.active
            )
            refreshed = existing.model_copy(
                update={
                    "status": status,
                    "last_seen_ts": now,
                    "ttl_expires_at": now + self._ttl,
                }
            )
            return self._repository.upsert(refreshed)

        # New attacker (or expired old binding): allocate a fresh logical binding.
        binding_id = str(uuid4())
        record = BindingRecord(
            binding_id=binding_id,
            attacker_key=request.attacker_key,
            backend_instance_id=f"ns-{binding_id[:8]}",
            status=BindingStatus.active,
            first_seen_ts=now,
            last_seen_ts=now,
            ttl_expires_at=now + self._ttl,
            volume_ref=f"vol-{binding_id[:8]}",
        )
        return self._repository.upsert(record)

    def heartbeat(self, binding_id: str, request: HeartbeatRequest) -> BindingRecord:
        """Mark a binding as active and extend its TTL window."""
        existing = self._repository.get_by_binding(binding_id)
        if existing is None:
            raise BindingNotFoundError(binding_id)
        # Heartbeat always moves the binding back to active and extends TTL.
        refreshed = existing.model_copy(
            update={
                "status": BindingStatus.active,
                "last_seen_ts": request.ts,
                "ttl_expires_at": request.ts + self._ttl,
            }
        )
        return self._repository.upsert(refreshed)

    def recycle(self, binding_id: str, request: RecycleRequest) -> BindingRecord:
        """Recycle a binding.

        Modes:
        - idle: keep state recoverable until TTL expires.
        - hard: expire immediately.
        """
        existing = self._repository.get_by_binding(binding_id)
        if existing is None:
            raise BindingNotFoundError(binding_id)
        now = utcnow()
        # "hard" recycle expires immediately; "idle" keeps recoverable state.
        ttl_expires_at = now if request.mode == "hard" else now + self._ttl
        updated = existing.model_copy(
            update={
                "status": BindingStatus.recycled,
                "last_seen_ts": now,
                "ttl_expires_at": ttl_expires_at,
            }
        )
        return self._repository.upsert(updated)

    def get(self, binding_id: str) -> BindingRecord:
        """Fetch one binding by binding_id or raise if missing."""
        existing = self._repository.get_by_binding(binding_id)
        if existing is None:
            raise BindingNotFoundError(binding_id)
        return existing

    def unlock_assets(self, binding_id: str, asset_ids: list[str]) -> BindingRecord:
        """Append one or more unlocked assets without duplicating entries."""
        existing = self._repository.get_by_binding(binding_id)
        if existing is None:
            raise BindingNotFoundError(binding_id)

        unlocked_assets = list(existing.unlocked_assets)
        for asset_id in asset_ids:
            if asset_id not in unlocked_assets:
                unlocked_assets.append(asset_id)

        updated = existing.model_copy(
            update={
                "status": BindingStatus.active,
                "last_seen_ts": utcnow(),
                "unlocked_assets": unlocked_assets,
            }
        )
        return self._repository.upsert(updated)
