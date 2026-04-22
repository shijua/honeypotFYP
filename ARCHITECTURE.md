# Architecture (Current State)

## Scope
This repository currently implements an MVP control loop across seven services:

- `binding_service`
- `cowrie`
- `entrypoint`
- `profiler`
- `controller`
- `gateway`
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

### 4) Entrypoint service
- Path: `services/entrypoint/*`
- Purpose: low-interaction public web honeypot for initial data collection.
- Core behavior:
  - capture arbitrary HTTP paths
  - resolve a sticky binding for the source attacker
  - persist a redacted observation
  - forward a normalized `FalcoEvent` into the profiler
  - return a plain `404 Not Found` response

### 5) Cowrie service
- Path: `services/cowrie/*`
- Purpose: ingest SSH honeypot telemetry from Cowrie JSON logs.
- Core behavior:
  - accept parsed Cowrie JSON events
  - resolve a sticky binding by `src_ip`
  - persist a sanitized Cowrie observation
  - load Cowrie event mappings from `data/cowrie/event_mappings.json`
  - only emit ATT&CK tags for clear behavior; keep metadata/ambiguous events as `cowrie_*` descriptive tags
  - forward a normalized `FalcoEvent` into the profiler only when the event mapping has `profile=true`
  - keep `cowrie.command.failed` as observation-only to avoid double-counting a command already seen as `cowrie.command.input`

### 6) Controller service
- Path: `services/controller/*`
- Purpose: decide which internal assets should be exposed next.
- Core behavior:
  - load T-Pot-inspired decoy template definitions from `data/assets/catalog.json`
  - filter assets by dependencies, unlock state, and unlock cap
  - score candidates with a light exploit/explore policy
  - emit `unlock` or `noop` actions plus explanatory `DecisionEvent` records

### 7) Gateway service
- Path: `services/gateway/*`
- Purpose: keep the live route/exposure view for each binding.
- Core behavior:
  - sync the latest binding status and exposed assets
  - retain route updates for each binding
  - expose a read API for the current gateway view

### 8) Orchestrator service
- Path: `services/orchestrator/*`
- Purpose: apply controller actions to the current binding state.
- Core behavior:
  - update unlocked assets on the binding
  - start template runtime records from `data/assets/catalog.json`
  - start a real Docker container for supported web templates
  - fall back to mock runtime records for unsupported templates
  - emit Falco-style monitoring events for asset lifecycle changes
  - sync route changes into the gateway state
  - recycle bindings while preserving recoverable attacker state

### 9) Repository layer
- Path: `services/binding_service/repository.py`
- Purpose: storage abstraction for the binding slice.
- Includes:
  - `BindingRepository` protocol (port interface).
  - `InMemoryBindingRepository` adapter (tests/local isolation).
  - `FileBindingRepository` adapter (default runtime).

Additional repositories now exist for:

- profiler evidence and profile snapshots
- entrypoint HTTP observations
- Cowrie SSH observations
- gateway route state
- controller asset catalog and tactic transitions

### 10) API layer
- Paths:
  - `services/binding_service/app.py`
  - `services/cowrie/app.py`
  - `services/entrypoint/app.py`
  - `services/profiler/app.py`
  - `services/controller/app.py`
  - `services/gateway/app.py`
  - `services/orchestrator/app.py`
- Purpose: expose the MVP lifecycle via FastAPI.
- Endpoints:
  - `POST /v1/bindings/resolve`
  - `POST /v1/bindings/{binding_id}/heartbeat`
  - `POST /v1/bindings/{binding_id}/recycle`
  - `GET /v1/bindings/{binding_id}`
  - `GET /healthz`
  - `GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD /{path}`
  - `POST /v1/cowrie/events`
  - `POST /v1/evidence/ingest`
  - `GET /v1/profiles/{attacker_key}`
  - `POST /v1/controller/tick`
  - `POST /v1/gateway/sync`
  - `GET /v1/gateway/bindings/{binding_id}`
  - `POST /v1/orchestration/apply`

## Request Flow
1. `entrypoint` captures an HTTP probe or `cowrie` ingests an SSH honeypot event.
2. `binding_service` resolves a sticky binding for that attacker.
3. `profiler` ingests the normalized event and refreshes the attacker profile.
4. `controller` reads the profile plus current unlocked assets and returns actions.
5. `orchestrator` applies those actions back onto the binding state.
6. `gateway` mirrors the current exposure/routing view for that binding.
7. Shared contracts keep the loop testable across service boundaries.

## Testing
- Unit: `tests/binding_service/test_unit_binding_service.py`
- Unit: `tests/profiler/test_unit_profiler_service.py`
- Unit: `tests/controller/test_unit_controller_service.py`
- Unit: `tests/cowrie/test_unit_cowrie_service.py`
- Unit: `tests/entrypoint/test_unit_entrypoint_service.py`
- Unit: `tests/gateway/test_unit_gateway_service.py`
- Unit: `tests/orchestrator/test_unit_orchestrator_service.py`
- Component: `tests/binding_service/test_component_binding_api.py`
- Component: `tests/profiler/test_component_profiler_api.py`
- Component: `tests/controller/test_component_controller_api.py`
- Component: `tests/cowrie/test_component_cowrie_api.py`
- Component: `tests/entrypoint/test_component_entrypoint_api.py`
- Component: `tests/gateway/test_component_gateway_api.py`
- Component: `tests/orchestrator/test_component_orchestrator_api.py`
- Contract: `tests/contracts/test_binding_contracts.py`
- Contract: `tests/contracts/test_mvp_contracts.py`
- Adapter: `tests/adapter/test_file_backed_runtime_adapters.py`
- Smoke: `tests/test_mvp_smoke.py`

## Notes
- Default local storage is file-backed under `data/runtime/`.
- Cowrie observations are stored in `data/runtime/cowrie_observations.json`.
- Cowrie profiler evidence is stored separately in `data/runtime/evidence.json`;
  observations are intake/audit records, while evidence affects profiles and controller decisions.
- Entrypoint observations are stored in `data/runtime/entrypoint_observations.json`.
- Falco should later run outside honeypot containers as node/runtime telemetry,
  while Cowrie logs capture SSH attacker interaction telemetry.
- Local Cowrie lab configuration lives in `deploy/cowrie/`; the log forwarder
  `scripts/forward_cowrie_json.py` bridges `cowrie.json` into the Cowrie API.
- Orchestration is still a mock control-plane adapter; it records
  `AssetRuntimeRecord` entries and can now start a small Docker-backed web
  template, but it does not manage Kubernetes pods/namespaces yet.
- The controller now loads its asset catalog from `data/assets/catalog.json`.
  The catalog contains MVP template metadata such as protocol, port, family,
  default settings, and source references, but these are not real
  Docker/Kubernetes manifests yet.
- Mock asset starts are converted into Falco-style `FalcoEvent` objects with
  `falco_rule="Honeynet asset template started"`. Real Falco will only observe
  these lifecycle events after a future Docker/Kubernetes adapter creates real
  workloads.
- Cowrie event priority, ATT&CK tags, descriptive `cowrie_*` tags, and
  profiler output fields are loaded from `data/cowrie/event_mappings.json`.
- Attack-graph generation is still planned but not implemented.
