# Architecture

## Scope
This repository currently implements a technique-informed dynamic honeynet across a small set of control-plane services, telemetry adapters, and runtime gateways.

Core control loop:
- `binding_service`
- `profiler`
- `controller`
- `orchestrator`
- `gateway`

Telemetry and attacker-facing adapters:
- `entrypoint`
- `cowrie`
- `opencanary`
- `high_interaction`

These are adapter categories, not one service per honeypot image. Concrete runtimes such as Mailoney, Dionaea, Glutton, Wordpot, OpenCanary, and Cowrie are catalog-selected backends that feed one of these adapters through gateway logs or sidecar forwarders. The asset id `honeytrap-generic` is a legacy/generic-capture name; its current generic capture backend is Glutton, while the normalized high-interaction source label remains `honeytrap` for existing rules and reports.

Runtime visibility and operator UI:
- `asset_gateway`
- `dashboard`

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
  - `opencanary` and `high_interaction` adapters for protocol and capture telemetry after routes exist
  - additional Web / multi-protocol entrypoints such as `SNARE + TANNER` and `Chameleon` are compatible design candidates, but they are not current repo services
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
  - later-stage assets such as `admin-jumpbox` or optional vulnerable environments
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

| Area | Main paths | Role |
| --- | --- | --- |
| Shared contracts | `libs/contracts/models.py` | Pydantic request/response/event models shared by services and tests. |
| Binding | `services/binding_service/*` | Sticky attacker-to-binding lifecycle, heartbeat, recycle, and unlocked asset state. |
| Telemetry adapters | `services/entrypoint/*`, `services/cowrie/*`, `services/opencanary/*`, `services/high_interaction/*` | Normalize public HTTP, SSH, protocol, and capture telemetry into profiler evidence. |
| Profiler | `services/profiler/*` | Map tagged events into ATT&CK evidence and maintain per-attacker profiles. |
| Controller | `services/controller/*` | Select `unlock`, `configure`, or `noop` actions from profile state, catalog gates, and the ATT&CK group prior. |
| Runtime apply | `services/orchestrator/*`, `services/gateway/*`, `services/asset_gateway/*` | Start/prewarm assets, record route state, and proxy only attacker-specific fixed-port traffic. |
| Dashboard | `services/dashboard/*` | Read-only view of runtime state, profiles, exposed assets, failures, and decision traces. |

## Runtime Backend To Adapter Mapping

| Runtime/backend | Adapter path | How telemetry reaches the adapter |
| --- | --- | --- |
| Public portal and internal HTTP assets | `entrypoint` | `public-portal-forwarder` and `internal-http-forwarder` read HTTP/gateway logs and POST normalized HTTP observations. |
| Public Cowrie, SSH canary, admin jumpbox Cowrie variants | `cowrie` | Cowrie JSON logs are tailed by `cowrie_json.py`; catalog sidecars are used when Cowrie runs as an adaptive internal backend. |
| OpenCanary Git/MySQL/Redis/FTP/SSH/Telnet/SMTP and protocol gateway events | `opencanary` | OpenCanary logs or `asset_gateway` protocol events are forwarded by `opencanary_json.py`. |
| Mailoney SMTP relay variant | `opencanary` | It is a same-port backend for `mail-relay`; SMTP route/protocol observations remain normalized through the protocol/OpenCanary adapter path. |
| Dionaea, Glutton generic capture, Wordpot capture variants | `high_interaction` | Backend logs or gateway high-interaction events are tailed by `high_interaction_logs.py` and POSTed to the high-interaction adapter. Glutton events are normalized with source label `honeytrap` for compatibility with the existing high-interaction rules. |

## Controller Policy

The controller loads internal asset definitions from `data/assets/catalog.json` and a generated ATT&CK group-technique prior from `data/technique_prior/attack_group_technique_prior.json`. The prior is built from local Enterprise ATT&CK STIX intrusion-set-to-technique relationships by `scripts/data/build_attack_group_prior.py`; optional public datasets under `vendor/datasets/` are validation material, not runtime training data.

Eligibility is controlled by catalog constraints: dependencies, unlock signals, runtime availability, existing unlock state, and unlock caps. Ranking is technique-first: for each candidate, expected gain sums `p_t * (1 - C_t)` over covered techniques, where `p_t` is prior support and `C_t` is current profile confidence. Configuration variants are follow-on reveals for already visible assets and must create an attacker-visible file, link, or backend change.

Runtime state remains file-backed under `data/runtime/`. The adaptive loop records reveal feedback for evaluation/debugging, but the controller does not use that feedback for ranking. Warm-standby runtimes may be started before a route exists, so later reveals can attach a route without exposing a new port early.

## API Surface

FastAPI services expose the control loop as small versioned endpoints: binding resolution/heartbeat/recycle, telemetry ingestion for entrypoint/Cowrie/OpenCanary/high-interaction events, profiler evidence/profile reads, controller ticks, orchestration apply/prewarm, gateway sync/read, and dashboard `/api/summary`. The exact request and response shapes live in `libs/contracts/models.py`.

## Request Flow
1. A user or attacker first interacts with the benign user surface, attacker-facing entrypoints, or both.
2. `entrypoint` captures HTTP anomalies, `cowrie` ingests SSH honeypot events, and protocol/capture adapters ingest OpenCanary or high-interaction backend telemetry when those routes exist.
3. `binding_service` resolves a sticky binding for that attacker.
4. `profiler` ingests normalized events and builds an initial or refined attacker profile.
5. `controller` reads the current profile, the ATT&CK group technique prior, the technique-aware asset catalog, and current unlocked assets before returning actions.
6. `orchestrator` applies those actions back onto the binding state and attempts to start any newly selected assets.
7. `gateway` mirrors the current exposure/routing view for that binding, separating reachable assets from failed ones.
8. `asset_gateway` reads the route table and proxies only attacker-specific fixed-port traffic to the selected backend.
9. `dashboard` renders the same runtime state and controller traces for inspection.
10. Shared contracts keep the loop testable across service boundaries.

## Testing And Operations

Use `README.md` for the shortest setup and command index. Use `EVALUATION.md` for prior, policy, port, and latency evaluation. Use `ATTACK_TESTING_GUIDE.md` for live/manual traffic that should produce telemetry and ATT&CK evidence.

Default local state is file-backed under `data/runtime/`. Observations are intake/audit records such as `cowrie_observations.json`, `entrypoint_observations.json`, `opencanary_observations.json`, and `high_interaction_observations.json`; profiler evidence lives in `evidence.json` and drives profile/controller behavior. Runtime route state lives in `asset_gateway_routes.json`.
