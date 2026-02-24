# Architecture (Current State)

## Scope
This repository currently implements one vertical slice: `binding_service`.

## Components

### 1) Contracts layer
- Path: `libs/contracts/models.py`
- Purpose: shared Pydantic schemas and enums used by service/API/tests.
- Key models:
  - `ResolveBindingRequest`, `HeartbeatRequest`, `RecycleRequest`
  - `BindingRecord`, `BindingStatus`

### 2) Domain layer
- Path: `services/binding_service/domain.py`
- Purpose: binding lifecycle rules.
- Core behavior:
  - `resolve`: sticky bind by `attacker_key`, create when missing/expired.
  - `heartbeat`: set `active`, refresh `last_seen_ts` and TTL.
  - `recycle`: `idle` keeps recoverable state, `hard` expires immediately.
  - `get`: read by `binding_id`.

### 3) Repository layer
- Path: `services/binding_service/repository.py`
- Purpose: storage abstraction.
- Includes:
  - `BindingRepository` protocol (port interface).
  - `InMemoryBindingRepository` adapter (current implementation).

### 4) API layer
- Path: `services/binding_service/app.py`
- Purpose: expose domain lifecycle via FastAPI.
- Endpoints:
  - `POST /v1/bindings/resolve`
  - `POST /v1/bindings/{binding_id}/heartbeat`
  - `POST /v1/bindings/{binding_id}/recycle`
  - `GET /v1/bindings/{binding_id}`

## Request Flow
1. Request enters FastAPI handler in `app.py`.
2. Handler calls `BindingService` in `domain.py`.
3. Service reads/writes via `BindingRepository`.
4. Response is serialized with contract models from `libs/contracts/models.py`.

## Testing
- Unit: `tests/binding_service/test_unit_binding_service.py`
- Component: `tests/binding_service/test_component_binding_api.py`
- Contract: `tests/contracts/test_binding_contracts.py`

## Notes
- Current storage is in-memory only.
- Other planned services (gateway/controller/profiler/attack_graph) are not implemented yet.
