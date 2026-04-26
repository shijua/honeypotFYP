# Dynamic Honeynet (Python Monorepo)

This repository implements a profiling-driven dynamic honeynet MVP with independently testable services.

- `services/binding_service`
- `services/cowrie`
- `services/entrypoint`
- `services/profiler`
- `services/controller`
- `services/gateway`
- `services/opencanary`
- `services/orchestrator`
- `libs/contracts`
- `libs/common`
- `data/assets/catalog.json`

## Environment model

The intended deployment model has three visibility layers:

- `Benign user surface`: normal user-facing pages and services that make the environment look like a real enterprise
- `Attacker-facing entrypoints`: the first public-facing collection points such as the public website HTTP backend and SSH honeypots
- `Adaptive internal assets`: internal services that are released gradually based on the current attacker profile

The profiling idea is:

```text
benign-surface anomalies provide baseline context
+ attacker-entrypoint telemetry provides explicit attack evidence
= initial attacker profile for adaptive internal asset selection
```

## Setup

```bash
python3.10 -m pip install -e ".[dev]"
```

The repository target is Python `3.10+`.

Repository data layout:

- `data/assets/catalog.json` is committed with the repo.
- `data/cowrie/event_mappings.json` is committed with the repo.
- `data/mitre/enterprise-attack.json` must be fetched locally before using the default profiler runtime.

One-line fetch command:

```bash
python scripts/fetch_mitre_attack_stix.py
```

## Test gates

```bash
pytest -m unit
pytest -m component
pytest -m contract
pytest -m e2e_smoke
pytest -m adapter
```

Run the current MVP suite with:

```bash
pytest -q tests/binding_service tests/cowrie tests/entrypoint tests/opencanary tests/profiler tests/controller tests/orchestrator tests/gateway tests/contracts tests/adapter tests/test_mvp_smoke.py
```

Simulation helpers and dashboard/script tests are kept in the main tree so they stay synchronized with the current compose stack.

## Service entrypoints

Each service has a FastAPI app object in `services/*/app.py`. Implemented entrypoints:

- `uvicorn services.binding_service.app:app --reload`
- `uvicorn services.cowrie.app:app --reload`
- `uvicorn services.entrypoint.app:app --reload`
- `uvicorn services.profiler.app:app --reload`
- `uvicorn services.controller.app:app --reload`
- `uvicorn services.gateway.app:app --reload`
- `uvicorn services.opencanary.app:app --reload`
- `uvicorn services.orchestrator.app:app --reload`

Current MVP flow:

```bash
HTTP/Cowrie/OpenCanary event -> resolve binding -> ingest evidence -> read profile -> controller tick -> orchestrator apply -> gateway sync
```

## Runtime storage

The default local runtime now persists state under `data/runtime/`:

- `bindings.json`
- `cowrie_observations.json`
- `entrypoint_observations.json`
- `opencanary_observations.json`
- `evidence.json`
- `profiles.json`
- `gateway_routes.json`

The controller asset catalog is now externalized at `data/assets/catalog.json`. Cowrie event mappings are externalized at `data/cowrie/event_mappings.json`. The profiler resolves tactic/technique relationships from the official MITRE ATT&CK `attack-stix-data` bundle at `data/mitre/enterprise-attack.json`.

## Simulation Helpers

Useful helper scripts are kept in `scripts/` and covered by tests:

```bash
./scripts/test_enterprise_compose.sh
./scripts/run_enterprise_actor_simulation.sh
python scripts/validate_asset_telemetry.py --asset-id internal-portal
.venv/bin/python scripts/summarize_adaptive_demo.py --write-report data/runtime/adaptive_demo_report.json
```

Use the manual flow in `ATTACK_TESTING_GUIDE.md` when you want to drive the attacker actions yourself.

## Enterprise Compose Draft

The enterprise-network deployment uses two compose files:

- `docker-compose.control.yml` runs the control plane.
- `docker-compose.enterprise.yml` runs the benign surface, attacker entrypoints, and currently real enterprise assets.

Copy `.env.example` to `.env` if local ports or bind addresses need to change. Keep `HOST_BIND_ADDRESS=127.0.0.1` for SSH-tunnel/local-only testing; use `HOST_BIND_ADDRESS=0.0.0.0` or a specific private IP if you want browser/terminal access from your LAN/VPN.

Reset old containers and runtime state before a fresh run:

```bash
./scripts/reset_enterprise_runtime.sh
```

Start the runnable stack without generating attacker traffic:

```bash
./scripts/start_enterprise_stack.sh
```

The enterprise slice includes `public-portal`, a public-portal access-log forwarder, Cowrie, the public website HTTP backend, `SNARE + TANNER`, OpenCanary telemetry plumbing, and the first internal portal. The public portal implements the proposalv2 benign-surface breadcrumbs: login/support/status/API pages, `/robots.txt`, fake backup files, fake `.env.old`, `phpinfo.php`, and frontend source-map honeytokens. Public portal nginx access logs are forwarded into the HTTP backend, so suspicious benign-surface visits become `entrypoint_observations` and cold-start profile evidence.

Current service roles:

| Service | Layer | Host port | Purpose |
| --- | --- | --- | --- |
| `public-portal` | benign user surface | `8080` | Real-looking public site and breadcrumb files such as `/robots.txt`, `/.env.old`, and source maps |
| `public-portal-forwarder` | telemetry bridge | none | Tails public portal nginx access logs and posts them to `entrypoint-observer` |
| `entrypoint-observer` | public website backend + direct HTTP test entrypoint | `8083` | Receives public portal breadcrumbs and handles explicit low-interaction HTTP probes |
| `cowrie` | attacker-facing entrypoint | `2222` | SSH interaction and command telemetry |
| `snare` + `tanner` | optional attacker-facing web clone | `8081` | Realistic cloned-web entrypoint when the images start cleanly |
| `opencanary-adapter` + `opencanary-forwarder` | adaptive asset telemetry | none | Collect logs from OpenCanary-backed internal assets after they are unlocked |
| `internal-portal` | internal baseline service | internal only in compose, `18080` when dynamically unlocked | First internal asset in the adaptive path |
| `binding-service`, `profiler`, `controller`, `orchestrator`, `gateway`, `adaptive-loop`, `dashboard` | control plane | dashboard on `8090`; APIs internal | Profiling, asset selection, runtime start, route state, and live monitoring |

OpenCanary is no longer an always-on attacker-facing entrypoint. OpenCanary telemetry is collected through `scripts/forward_opencanary_json.py`, which tails `deploy/opencanary/var/opencanary.log` and posts events into `services/opencanary`. Adaptive internal OpenCanary assets mount that shared log directory, so their Git/MySQL/Redis/HTTP/FTP/SSH/Telnet events flow into the dashboard after the controller unlocks them.

The adaptive internal catalog includes standalone OpenCanary assets for Git, MySQL, Redis, HTTP, FTP, SSH, and Telnet. They are not enabled by changing one shared OpenCanary configuration; the orchestrator starts a separate container per asset when the controller unlocks it. Default host ports can be overridden in `.env`:

```bash
GIT_INTERNAL_PORT=19418
OPS_DB_PORT=13306
REDIS_CACHE_PORT=16379
WEB_ADMIN_CONSOLE_PORT=18081
FTP_ARCHIVE_PORT=12121
SSH_CANARY_PORT=12222
LEGACY_TELNET_PORT=12323
```

Vulnerable internal assets are now represented in the normal asset catalog. Clone Vulhub under the ignored `vendor/vulhub/` path before triggering `log4shell-app`:

```bash
git clone --depth 1 https://github.com/vulhub/vulhub.git vendor/vulhub
```

`log4shell-app` points at `vendor/vulhub/log4j/CVE-2021-44228/docker-compose.yml` and is started by the orchestrator through the compose-backed internal asset runtime after its dependency chain is satisfied. If that compose file is missing, the orchestrator records `log4shell-app` as a failed asset so the dashboard shows the missing dependency clearly. Only run Vulhub scenarios in an isolated lab.

The manual Vulhub helper remains available for isolated experiments that should not go through the adaptive path:

```bash
./scripts/start_vulhub_asset.sh --root vendor/vulhub --scenario spring/CVE-2022-22947
```

Validate runtime/gateway/dashboard data after opening assets:

```bash
python scripts/validate_asset_telemetry.py --require-observed
python scripts/validate_asset_telemetry.py --asset-id log4shell-app
```

Live monitoring dashboard:

```bash
TARGET_HOST=127.0.0.1
curl http://$TARGET_HOST:${DASHBOARD_PORT:-8090}/healthz
```

Then open `http://$TARGET_HOST:${DASHBOARD_PORT:-8090}/` in a browser.

The dashboard includes a Pipeline Health panel that traces the live path from public surface access logs to HTTP/Cowrie/OpenCanary forwarders, adapters, profile/controller, gateway, and dashboard state. This is the first place to look when public portal probes, raw Cowrie commands, OpenCanary internal asset probes, or public website backend probes do not appear in the profile view.

Manual actor check after startup:

```bash
TARGET_HOST=127.0.0.1
curl http://$TARGET_HOST:8080/
curl -i -A "sqlmap/1.8 manual-test" http://$TARGET_HOST:8083/.env
ssh -p 2222 root@$TARGET_HOST
curl http://$TARGET_HOST:18080/
```

The default compose stack includes an adaptive loop, so new entrypoint/Cowrie profile evidence can trigger controller/orchestrator asset unlocks without manually calling those APIs.

The full rationale and Kubernetes mapping are in `DEPLOYMENT_DRAFT.md`.
