# Architecture (Current State)

## Scope
This repository currently implements an MVP control loop across four services:

- `binding_service`
- `profiler`
- `controller`
- `orchestrator`

## Components

### 1) Contracts layer
- Path: `libs/contracts/models.py`
- Purpose: shared Pydantic schemas and enums used by service/API/tests.
- Key models:
  - `ResolveBindingRequest`, `HeartbeatRequest`, `RecycleRequest`
  - `BindingRecord`, `BindingStatus`
  - `FalcoEvent`, `TechniqueEvidence`, `ProfileSnapshot`
  - `ControllerTickRequest`, `ControllerTickResponse`
  - `OrchestratorApplyRequest`, `OrchestratorApplyResponse`

### 2) Binding service
- Path: `services/binding_service/domain.py`
- Purpose: binding lifecycle rules.
- Core behavior:
  - `resolve`: sticky bind by `attacker_key`, create when missing/expired.
  - `heartbeat`: set `active`, refresh `last_seen_ts` and TTL.
  - `recycle`: `idle` keeps recoverable state, `hard` expires immediately.
  - `get`: read by `binding_id`.
  - `unlock_assets`: persist newly exposed internal assets on the binding.

### 3) Profiler service
- Path: `services/profiler/*`
- Purpose: translate runtime events into ATT&CK-oriented evidence and attacker state.
- Core behavior:
  - ingest one `FalcoEvent`
  - map it to one or more `TechniqueEvidence`
  - aggregate confidence by tactic and technique
  - maintain recent tactics, techniques, and evidence ids for controller input

### 4) Controller service
- Path: `services/controller/*`
- Purpose: decide which internal assets should be exposed next.
- Core behavior:
  - filter assets by dependencies, unlock state, and unlock cap
  - score candidates with a light exploit/explore policy
  - emit `unlock` or `noop` actions plus explanatory `DecisionEvent` records

### 5) Orchestrator service
- Path: `services/orchestrator/*`
- Purpose: apply controller actions to the current binding state.
- Core behavior:
  - update unlocked assets on the binding
  - record mock route updates
  - recycle bindings while preserving recoverable attacker state

### 6) Repository layer
- Path: `services/binding_service/repository.py`
- Purpose: storage abstraction for the binding slice.
- Includes:
  - `BindingRepository` protocol (port interface).
  - `InMemoryBindingRepository` adapter (current implementation).

Additional in-memory repositories exist for:

- profiler evidence and profile snapshots
- controller asset catalog and tactic transitions
- orchestrator route state journal

### 7) API layer
- Paths:
  - `services/binding_service/app.py`
  - `services/profiler/app.py`
  - `services/controller/app.py`
  - `services/orchestrator/app.py`
- Purpose: expose the MVP lifecycle via FastAPI.
- Endpoints:
  - `POST /v1/bindings/resolve`
  - `POST /v1/bindings/{binding_id}/heartbeat`
  - `POST /v1/bindings/{binding_id}/recycle`
  - `GET /v1/bindings/{binding_id}`
  - `POST /v1/evidence/ingest`
  - `GET /v1/profiles/{attacker_key}`
  - `POST /v1/controller/tick`
  - `POST /v1/orchestration/apply`

## Request Flow
1. `binding_service` resolves a sticky binding for one attacker.
2. `profiler` ingests Falco-style evidence and refreshes the attacker profile.
3. `controller` reads the profile plus current unlocked assets and returns actions.
4. `orchestrator` applies those actions back onto the binding state.
5. Shared contracts keep the loop testable across service boundaries.

## Testing
- Unit: `tests/binding_service/test_unit_binding_service.py`
- Unit: `tests/profiler/test_unit_profiler_service.py`
- Unit: `tests/controller/test_unit_controller_service.py`
- Unit: `tests/orchestrator/test_unit_orchestrator_service.py`
- Component: `tests/binding_service/test_component_binding_api.py`
- Component: `tests/profiler/test_component_profiler_api.py`
- Component: `tests/controller/test_component_controller_api.py`
- Component: `tests/orchestrator/test_component_orchestrator_api.py`
- Contract: `tests/contracts/test_binding_contracts.py`
- Contract: `tests/contracts/test_mvp_contracts.py`
- Smoke: `tests/test_mvp_smoke.py`

## Notes
- Current storage is in-memory only.
- Orchestration is still a mock control-plane adapter; it does not start real containers or pods.
- Gateway and attack-graph slices are still planned but not implemented.
