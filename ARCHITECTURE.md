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
- `sigma`: read compatible Sigma YAML rules directly from `data/detections/cowrie_sigma:vendor/sigma/rules/linux`
- `hybrid`: load local first, then runtime Sigma, with duplicate `name + technique_id` mappings deduplicated

The mode is selected by `HONEYPOT_COWRIE_COMMAND_MAPPING_MODE` and loaded through `RuntimeConfig.from_env()`. The default `hybrid` mode combines `data/cowrie/command_mapping_rules.json` with the repo-owned `data/detections/cowrie_sigma` rules and optional `vendor/sigma/rules/linux` rules when that checkout exists. `HONEYPOT_COWRIE_SIGMA_RULES_PATH` accepts one or more `:`-separated roots, so experiments can widen or narrow the Sigma scope without replacing the project rules. Runtime Sigma support treats the configured folders as the scope and imports rule conditions it can express from one Cowrie command: process/image fields, command-line fields, auditd `EXECVE` arguments, and simple keyword lists. The supported condition subset includes standalone selections, `selection_a and selection_b`, `all of selection_*`, `1 of selection_*`, and `selection and not filter_*`. Unsupported fields are skipped rather than weakened into noisy matches. Matching remains real-time after the first lazy load. Sigma correlation or multi-event sequence rules still require a separate stateful correlation layer because Cowrie emits one command event at a time.

### 6) Controller service
- Path: `services/controller/*`
- Purpose: decide which internal assets should be exposed next.
- Core behavior:
  - load runtime asset definitions from `data/assets/catalog.json`
  - load a file-backed ATT&CK group-technique prior from `data/technique_prior/attack_group_technique_prior.json`
  - filter assets by hard dependencies, unlock signals, runtime availability, unlock state, and unlock cap
  - classify candidates as `recommended` when the group prior suggests an unseen technique, `continuation` when the asset enriches a thresholded observed technique, or `bootstrap` for the first internal portal reveal; these labels explain the evidence source and do not normally impose a priority class
  - score follow-on `configuration` candidates for assets that are already visible, using catalog `configuration_variants` and the same profile/dependency gates
  - order eligible assets by bootstrap/configuration structural exceptions, expected new technique gain, matched dependency markers, telemetry value, and asset id
  - keep family matching, configuration reveal context, and same-port upgrade context explicit in decision details
  - allow `internal-portal` as the first bootstrap discovery surface when profile evidence exists
  - emit `unlock`, `configure`, or `noop` actions plus structured `DecisionEvent.details` containing selected technique, candidate type, scores, rejected reasons, configuration ids, and group-prior status

#### ATT&CK group prior
The runtime prior is derived from local Enterprise ATT&CK STIX by `scripts/data/build_attack_group_prior.py`. It parses active `intrusion-set --uses--> attack-pattern` relationships into group technique sets and uses a small collaborative-filtering lookup at runtime: compare the binding's thresholded observed techniques to ATT&CK group technique sets, then recommend not-yet-observed techniques with normalized support. The builder does not fetch data or infer missing labels. `data/technique_prior/attack_group_technique_prior.json` is generated local state and ignored by git; missing files are allowed at startup but health reports the prior as degraded. Optional public datasets under `vendor/datasets/` remain useful for offline validation, but they are not the active runtime prior.

#### Technique-aware catalogue metadata
The shared `AssetDefinition` API does not add new top-level fields for selection metadata. Instead, each runtime internal asset declares `default_settings.selection_profile` with `asset_group`, `covered_techniques`, `optional_dependency_signals`, `telemetry_value`, `tactic_difficulties`, `reveal_outputs`, and `selection_notes`. `covered_techniques` must be valid Enterprise ATT&CK technique or sub-technique ids. Older fields such as `covers_tactics`, `dependencies`, and `unlock_signals` remain compatibility and hard-gate fields.
`expected_technique_gain` is the main ordering value: it sums `p_t * (1 - C_t)` over the candidate's covered techniques, where `p_t` is ATT&CK group-prior support and `C_t` is current profile confidence for that exact technique. Repeated behavior is therefore handled by continuous confidence: as the candidate technique's confidence rises, the novelty factor decreases and similar assets fall in the ordering. `telemetry_value` is a 0-1 catalog priority used only as a deterministic tie-break after expected gain and matched dependency markers; it says how useful that asset is expected to be once it is otherwise eligible, not how likely the attacker is to choose it.

Assets may also declare `default_settings.configuration_variants`. These are follow-on reveals for an asset that is already open, and each active variant must create an attacker-visible change. HTTP content variants write per-binding static files or links. Protocol variants either point to a concrete `target_asset_id` or declare a `target_runtime` that swaps the current asset to a real Docker backend on the same attacker-facing port, such as seeded Git, seeded Redis, Mailoney, Cowrie, or an OpenCanary banner profile. Runtime manifests are only audit records; they are not counted as a configuration reveal unless a file/link or target backend is visible to the attacker. Binding state stores applied variants under `revealed_configurations`, so the controller does not repeat the same configuration reveal for the same attacker.

#### Reveal feedback storage

The adaptive loop records applied reveal choices in `data/runtime/reveal_feedback.json` for evaluation and debugging. Later evidence that references the revealed `source_ref.asset_id` marks the pending reveal `useful` when it carries a tactic/technique, `shallow` when it only touches the asset, or `ignored` after `feedback_window_seconds`. The controller does not read this file for ranking.

#### Evaluation layers

The evaluation path is intentionally split by failure mode. `scripts/evaluation/reveal_policy.py` is the offline policy check: it compares reveal/no-reveal behavior without Docker. `scripts/evaluation/reveal_port_simulation.py --mode controller-only` checks whether scenario profiles select the expected asset/action/port without Docker. `scripts/evaluation/reveal_port_simulation.py --mode live-apply` starts or reuses the compose stack, applies controller actions, and verifies concrete `attacker_key + asset_id + public_port` routes in `data/runtime/asset_gateway_routes.json`. `live-apply` does not execute attacker traffic. Manual attacker-facing probes in `ATTACK_TESTING_GUIDE.md` cover HTTP configuration files and high-interaction capture responses. `scripts/evaluation/runtime_latency.py` measures binding, orchestrator, runtime-start, and route-visibility latency.

Warm-standby runtimes are a latency optimization for selected catalog assets. The orchestrator can start their Docker backend for a binding without writing an asset-gateway route, so the attacker does not see a new port. When the controller later reveals that asset, the runtime is reused and only the gateway route is attached.

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
  - prewarm selected Docker containers without exposing routes
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
- controller asset catalog and ATT&CK group technique prior

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
5. `controller` reads the current profile, the ATT&CK group technique prior, the technique-aware asset catalog, and current unlocked assets before returning actions.
6. `orchestrator` applies those actions back onto the binding state and attempts to start any newly selected assets.
7. `gateway` mirrors the current exposure/routing view for that binding, separating reachable assets from failed ones.
8. Shared contracts keep the loop testable across service boundaries.

## Testing And Operations

Use `README.md` for the shortest setup and command index. Use `EVALUATION.md` for prior, policy, port, and latency evaluation. Use `ATTACK_TESTING_GUIDE.md` for live/manual traffic that should produce telemetry and ATT&CK evidence.

Default local state is file-backed under `data/runtime/`. Observations are intake/audit records such as `cowrie_observations.json`, `entrypoint_observations.json`, `opencanary_observations.json`, and `high_interaction_observations.json`; profiler evidence lives in `evidence.json` and drives profile/controller behavior. Runtime route state lives in `asset_gateway_routes.json`.
