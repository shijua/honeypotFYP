# Dynamic Honeynet (Python Monorepo)

This repository implements a profiling-driven dynamic honeynet MVP with independently testable services.

- `services/binding_service`
- `services/cowrie`
- `services/entrypoint`
- `services/profiler`
- `services/controller`
- `services/gateway`
- `services/orchestrator`
- `libs/contracts`
- `libs/common`
- `data/assets/catalog.json`

## Environment model

The intended deployment model has three visibility layers:

- `Benign user surface`: normal user-facing pages and services that make the environment look like a real enterprise
- `Attacker-facing entrypoints`: the first public-facing collection points such as HTTP entrypoints and SSH honeypots
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
pytest -q tests/binding_service tests/cowrie tests/entrypoint tests/profiler tests/controller tests/orchestrator tests/gateway tests/contracts tests/adapter tests/test_mvp_smoke.py
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
- `uvicorn services.orchestrator.app:app --reload`

Current MVP flow:

```bash
HTTP/Cowrie event -> resolve binding -> ingest evidence -> read profile -> controller tick -> orchestrator apply -> gateway sync
```

## Runtime storage

The default local runtime now persists state under `data/runtime/`:

- `bindings.json`
- `cowrie_observations.json`
- `entrypoint_observations.json`
- `evidence.json`
- `profiles.json`
- `gateway_routes.json`

The controller asset catalog is now externalized at `data/assets/catalog.json`. Cowrie event mappings are externalized at `data/cowrie/event_mappings.json`. The profiler resolves tactic/technique relationships from the official MITRE ATT&CK `attack-stix-data` bundle at `data/mitre/enterprise-attack.json`.

## Simulation Helpers

Useful helper scripts are kept in `scripts/` and covered by tests:

```bash
./scripts/test_enterprise_compose.sh
./scripts/run_enterprise_actor_simulation.sh
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

The enterprise slice includes `public-portal`, Cowrie, the HTTP observer, `SNARE + TANNER`, `Chameleon`, `mail-relay`, and the first internal portal. Chameleon publishes a deliberately small protocol subset: HTTP, SSH, Redis, and MySQL.

To attach one locally cloned Vulhub scenario to the honeynet internal network:

```bash
./scripts/start_vulhub_asset.sh --root vendor/vulhub --scenario spring/CVE-2022-22947
```

Clone Vulhub outside the normal committed source tree or under `vendor/vulhub/`, which is ignored by git. The helper script is a temporary bridge for local testing; the correct long-term integration is a compose-backed internal asset runtime in the orchestrator. Only run Vulhub scenarios in an isolated lab.

Live monitoring dashboard:

```bash
TARGET_HOST=127.0.0.1
curl http://$TARGET_HOST:${DASHBOARD_PORT:-8090}/healthz
```

Then open `http://$TARGET_HOST:${DASHBOARD_PORT:-8090}/` in a browser.

The dashboard includes a Pipeline Health panel that traces the live path from public surface to HTTP/Cowrie entrypoints, forwarder, adapter, profile/controller, gateway, and dashboard state. This is the first place to look when raw Cowrie commands or HTTP probes do not appear in the profile view.

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
