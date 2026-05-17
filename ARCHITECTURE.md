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

## Environment Model
The intended deployment model is now organized into three visibility layers:

### 1) Benign user surface
- Purpose: the normal user-facing area that makes the environment look like a real enterprise.
- Typical content:
  - public website pages
  - normal login pages or portals
  - routine employee-facing or customer-facing pages
- Design role:
  - provide baseline context before the system sees explicit attacker behavior
  - support cold-start profiling by recording anomalous navigation, login attempts, path probing, and scan-like access patterns

### 2) Attacker-facing entrypoints
- Purpose: the first explicitly suspicious interaction points exposed to scanning, probing, and credential attempts.
- Current examples:
  - `entrypoint` for low-interaction HTTP capture
  - `cowrie` for SSH interaction telemetry
  - future Web / multi-protocol entrypoints such as `SNARE + TANNER` and `Chameleon`
- Design role:
  - collect high-signal early attack telemetry
  - refine the initial attacker profile produced from benign-surface anomalies

### 3) Adaptive internal assets
- Purpose: internal services that are not all exposed at once and are instead released gradually based on attacker behavior.
- Current examples:
  - `internal-portal`
  - `git-internal`
  - `mail-relay`
  - `redis-cache`
  - later-stage assets such as `admin-jumpbox` or future vulnerable environments
- Design role:
  - implement the adaptive deception step
  - guide the attacker deeper into the controlled environment using the current profile

## Cold-start profiling idea
The system does not treat entrypoint activity as the only source of initial judgment. Instead, it combines:

- anomalous behavior observed on the benign user surface
- explicit attack behavior observed on attacker-facing entrypoints

to build an initial attacker profile before selecting which internal assets to expose.

In short:

```text
benign-surface signals provide baseline context
+ attacker-entrypoint telemetry provides explicit attack evidence
= initial attacker profile for adaptive internal asset selection
```

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
  - match suspicious public and internal HTTP probes with Sigma YAML rules from `data/detections/http_sigma`
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
  - map `cowrie.command.input` values through the configured command mapping catalog
  - only emit ATT&CK tags for clear behavior; keep metadata/ambiguous events as `cowrie_*` descriptive tags
  - forward a normalized `FalcoEvent` into the profiler only when the event mapping has `profile=true`
  - keep `cowrie.command.failed` as observation-only to avoid double-counting a command already seen as `cowrie.command.input`

#### Cowrie command mapping modes
Cowrie command detection is intentionally separated from the live SSH intake path. The runtime loads the selected catalog lazily on first command input, then matches attacker-entered shell text against in-memory rules.

Supported modes:

- `local`: load `data/cowrie/command_mapping_rules.json` only
- `sigma`: read compatible Sigma YAML rules directly from `vendor/sigma/rules/linux`
- `hybrid`: load local first, then runtime Sigma, with duplicate `name + technique_id` mappings deduplicated

The mode is selected by `HONEYPOT_COWRIE_COMMAND_MAPPING_MODE` and loaded through `RuntimeConfig.from_env()`. `sigma` and `hybrid` require a SigmaHQ checkout under `vendor/sigma` unless `HONEYPOT_COWRIE_SIGMA_RULES_PATH` points somewhere else. Runtime Sigma support treats the configured folder as the scope and imports rule conditions it can express from one Cowrie command: process/image fields, command-line fields, auditd `EXECVE` arguments, and simple keyword lists. The supported condition subset includes standalone selections, `selection_a and selection_b`, `all of selection_*`, `1 of selection_*`, and `selection and not filter_*`. Unsupported fields are skipped rather than weakened into noisy matches. Matching remains real-time after the first lazy load. Sigma correlation or multi-event sequence rules still require a separate stateful correlation layer because Cowrie emits one command event at a time.

### 6) Controller service
- Path: `services/controller/*`
- Purpose: decide which internal assets should be exposed next.
- Core behavior:
  - load runtime asset definitions from `data/assets/catalog.json`
  - load a file-backed public ATT&CK transition prior from `data/transitions/technique_transition_prior.json`
  - filter assets by hard dependencies, unlock signals, runtime availability, unlock state, and unlock cap
  - score techniques with `Q(t)=0.6*C_t+0.4*p_K(t)`, where `C_t` is current profile confidence and `p_K(t)` is the recent-technique transition prior with supported order-2/order-3 hybrid backoff; runtime order-2 uses `max(base, 0.60*P(next|current)+0.25*P(next|previous,current)+0.15*base)`, and runtime order-3 uses `max(order2_score, 0.45*P(next|current)+0.20*P(next|previous,current)+0.25*P(next|previous2,previous,current)+0.10*order2_score)`
  - score exploit assets with technique score, soft dependency match, and catalog telemetry value
  - score plausible explore assets with complementary technique coverage, different asset groups, uncertainty, and reveal feedback coverage gap
  - allow `internal-portal` as the first bootstrap discovery surface when profile evidence exists
  - emit `unlock` or `noop` actions plus structured `DecisionEvent.details` containing selected technique, scores, rejected reasons, dataset-prior status, and feedback contribution

#### Public transition prior
The public transition prior is derived from local public ATT&CK-labelled datasets by `scripts/data/build_attack_transition_prior.py`. Raw datasets are kept under ignored paths such as `vendor/datasets/`; `scripts/data/fetch_public_attack_datasets.py` can fetch the small real-data default profile and can explicitly fetch Mordor/OTRF metadata plus all metadata-declared zip entries, including Host, Network, and Cloud files. PWNJUTSU is treated as index/dry-run until local files can expose ordered `case_id + timestamp/order + technique` records. The repo only stores importer code, tests, schema expectations, and optionally generated derived prior files. Input records are normalized into traces with `case_id`, `source_dataset`, and ordered events. Mordor metadata is expanded from ordered `attack_mappings`; records without ATT&CK technique ids are counted in the build report but do not contribute transition edges. The default prior uses trace-balanced order-1 bigram counts with a small global fallback and also emits order-2 `P(next | previous,current)` and order-3 `P(next | previous2,previous,current)` edges. The controller uses higher-order context only when support is high enough, and falls back to the order-1 prior otherwise. Event-count mode remains available as a baseline. The controller treats this prior as a ranking signal only; asset eligibility still comes from catalog hard gates such as dependencies and unlock signals.

#### Technique-aware catalogue metadata
The shared `AssetDefinition` API does not add new top-level fields for selection metadata. Instead, each runtime internal asset declares `default_settings.selection_profile` with `asset_group`, `covered_techniques`, `optional_dependency_signals`, `telemetry_value`, `tactic_difficulties`, `reveal_outputs`, and `selection_notes`. `covered_techniques` must be valid Enterprise ATT&CK technique or sub-technique ids. Older fields such as `covers_tactics`, `dependencies`, and `unlock_signals` remain compatibility and hard-gate fields.

#### Reveal feedback
The adaptive loop records revealed asset choices in `data/runtime/reveal_feedback.json`. Later evidence that references `source_ref.asset_id` marks a pending reveal useful; pending reveals that age past the feedback window are marked ignored. The current controller uses this feedback as a coverage-gap signal for exploration so under-sampled plausible asset groups can still be tried.

#### Evaluation metrics

Public-prior quality is evaluated offline with held-out traces, not by assuming that more data automatically improves the controller. `scripts/evaluation/technique_prior.py` reports labelled/skipped event counts, trace count, top1/top3/top5/top10 next-technique accuracy, MRR, negative log likelihood, unseen-source rate, train/test edge counts, and source-level breakdown. Live system overhead is measured separately with `scripts/evaluation/runtime_latency.py`, which records binding resolve latency, orchestrator apply latency, Docker-backed runtime startup as observed by the orchestrator response, and asset-gateway route visibility latency.

### 7) Gateway service
- Path: `services/gateway/*`
- Purpose: keep the live route/exposure view for each binding.
- Core behavior:
  - sync the latest binding status and exposed assets
  - track failed assets separately from currently reachable assets
  - retain route updates for each binding
  - expose a read API for the current gateway view

### 8) Orchestrator service
- Path: `services/orchestrator/*`
- Purpose: apply controller actions to the current binding state.
- Core behavior:
  - update unlocked assets on the binding
  - start template runtime records from `data/assets/catalog.json`
  - start real Docker containers for supported catalog runtimes
  - fall back to mock runtime records for unsupported templates
  - emit Falco-style monitoring events for asset lifecycle changes
  - sync route changes into the gateway state
  - recycle bindings while preserving recoverable attacker state

### 9) Repository layer
- Path: `services/binding_service/repository.py`
- Purpose: storage abstraction for the binding slice.
- Includes:
  - `BindingRepository` protocol (port interface).
  - `FileBindingRepository` adapter (default runtime).
  - test doubles live under `tests/support/inmemory_repositories.py`.

Additional repositories now exist for:

- profiler evidence and profile snapshots
- entrypoint HTTP observations
- Cowrie SSH observations
- gateway route state
- controller asset catalog, public technique transitions, and reveal feedback

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
1. A user or attacker first interacts with the benign user surface, attacker-facing entrypoints, or both.
2. `entrypoint` captures HTTP anomalies and `cowrie` ingests SSH honeypot events.
3. `binding_service` resolves a sticky binding for that attacker.
4. `profiler` ingests normalized events and builds an initial or refined attacker profile.
5. `controller` reads the current profile, the public transition prior, the technique-aware asset catalog, current unlocked assets, and reveal feedback before returning actions.
6. `orchestrator` applies those actions back onto the binding state and attempts to start any newly selected assets.
7. `gateway` mirrors the current exposure/routing view for that binding, separating reachable assets from failed ones.
8. Shared contracts keep the loop testable across service boundaries.

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
- Cowrie profiler evidence is stored separately in `data/runtime/evidence.json`; observations are intake/audit records, while evidence affects profiles and controller decisions.
- Entrypoint observations are stored in `data/runtime/entrypoint_observations.json`.
- Falco should later run outside honeypot containers as node/runtime telemetry, while Cowrie logs capture SSH attacker interaction telemetry.
- Local Cowrie lab configuration lives in `deploy/cowrie/`; the log forwarder `scripts/forwarders/cowrie_json.py` bridges `cowrie.json` into the Cowrie API.
- Orchestration records `AssetRuntimeRecord` entries and can start selected Docker-backed runtimes, but it does not manage Kubernetes pods/namespaces yet.
- The controller now loads its asset catalog from `data/assets/catalog.json`. The catalog contains MVP template metadata such as protocol, port, family, default settings, source references, and selected Docker runtime specs. These are still MVP runtime specs, not full Docker Compose/Kubernetes manifests.
- Current real-demo status:
  - `internal-portal` is the first verified real internal asset and currently uses a stable `nginx:alpine` runtime.
  - `gateway.exposed_assets` means currently reachable assets, while failed Docker starts/exited containers are tracked separately as failed assets.
  - `redis-cache` is still a known failed Docker-backed asset in the local demo and should be treated as an unresolved runtime/integration issue.
- Mock asset starts are converted into Falco-style `FalcoEvent` objects with `falco_rule="Honeynet asset template started"`. Real Falco will only observe these lifecycle events after a future Docker/Kubernetes adapter creates real workloads.
- Cowrie event priority, ATT&CK tags, descriptive `cowrie_*` tags, and profiler output fields are loaded from `data/cowrie/event_mappings.json`.
- Attack-graph generation is still planned but not implemented.
