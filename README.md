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
- `data/mitre/enterprise-attack.json` must be fetched locally before using the
  default profiler runtime.

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

## Service entrypoints

Each service has a FastAPI app object in `services/*/app.py`.
Implemented entrypoints:

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

## Current demo status

The current adaptive demo has one verified real internal asset path:

- `internal-portal` now uses a stable web runtime based on `nginx:alpine`
- this asset is the first internal web foothold after Cowrie activity
- `git-internal` and several later assets still remain mock-only unless explicitly backed by a real runtime
- `redis-cache` is still known to fail in the current Docker-backed demo path and should be treated as an unresolved runtime issue rather than a controller decision issue

The most useful short demo today is:

```bash
Cowrie interaction -> profile update -> controller unlocks internal-portal -> orchestrator opens 127.0.0.1:18080
```

Minimal validation commands:

```bash
./scripts/run_adaptive_cowrie_demo.sh cleanup
./scripts/run_adaptive_cowrie_demo.sh
docker ps -a --filter label=honeynet.mvp=true --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
.venv/bin/python scripts/summarize_adaptive_demo.py --write-report data/runtime/adaptive_demo_report.json
```

If the demo is healthy, `internal-portal` should appear as:

```bash
nginx:alpine   Up ...
```

## Local Cowrie honeypot

The repo includes a local Cowrie Docker setup in `deploy/cowrie/`.

Quick start:

```bash
./scripts/run_local_cowrie_lab.sh
```

The quick-start command opens `ssh -p 2222 root@127.0.0.1` and shuts the
adapter, log forwarder, and Cowrie container down when the SSH session exits.
On startup it also stops the previous `dynamic-honeynet-cowrie` compose
container and a legacy container named `cowrie`, if present. If another process
still owns `2222`, the script reports the conflict instead of switching ports.
It rotates the previous raw Cowrie JSON log before each run so the current
session is forwarded cleanly. It also clears the local Cowrie demo runtime
files under `data/runtime/`; the file-backed repositories recreate missing JSON
files with their default shapes when the adapter starts.

Manual mode:

Start the adapter API:

```bash
/home/wh1322/honeypot/.venv/bin/python -m uvicorn services.cowrie.app:app --host 127.0.0.1 --port 8081
```

Start Cowrie in another terminal:

```bash
mkdir -p deploy/cowrie/var/log/cowrie
mkdir -p deploy/cowrie/var/lib/cowrie/tty
chmod 0777 deploy/cowrie/var deploy/cowrie/var/log deploy/cowrie/var/log/cowrie deploy/cowrie/var/lib deploy/cowrie/var/lib/cowrie deploy/cowrie/var/lib/cowrie/tty
docker-compose -f deploy/cowrie/docker-compose.yml up
```

Forward Cowrie JSON logs into the adapter:

```bash
/home/wh1322/honeypot/.venv/bin/python scripts/forward_cowrie_json.py \
  --log-file deploy/cowrie/var/log/cowrie/cowrie.json \
  --adapter-url http://127.0.0.1:8081/v1/cowrie/events
```

Generate a local SSH event:

```bash
ssh -p 2222 root@127.0.0.1
```

## Runtime storage

The default local runtime now persists state under `data/runtime/`:

- `bindings.json`
- `cowrie_observations.json`
- `entrypoint_observations.json`
- `evidence.json`
- `profiles.json`
- `gateway_routes.json`

The controller asset catalog is now externalized at `data/assets/catalog.json`.
Cowrie event mappings are externalized at `data/cowrie/event_mappings.json`.
The profiler resolves tactic/technique relationships from the official MITRE
ATT&CK `attack-stix-data` bundle at `data/mitre/enterprise-attack.json`.
