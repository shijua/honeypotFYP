# Dynamic Honeynet (Python Monorepo)

This repository implements a profiling-driven dynamic honeynet MVP with independently testable services.

- `services/binding_service`
- `services/profiler`
- `services/controller`
- `services/gateway`
- `services/orchestrator`
- `libs/contracts`
- `libs/common`
- `data/assets/catalog.json`

## Setup

```bash
python3.10 -m pip install -e ".[dev]"
```

The repository target is Python `3.10+`.

Repository data layout:

- `data/assets/catalog.json` is committed with the repo.
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
pytest -q tests/binding_service tests/profiler tests/controller tests/orchestrator tests/contracts tests/test_mvp_smoke.py
```

## Service entrypoints

Each service has a FastAPI app object in `services/*/app.py`.
Implemented entrypoints:

- `uvicorn services.binding_service.app:app --reload`
- `uvicorn services.profiler.app:app --reload`
- `uvicorn services.controller.app:app --reload`
- `uvicorn services.gateway.app:app --reload`
- `uvicorn services.orchestrator.app:app --reload`

Current MVP flow:

```bash
resolve binding -> ingest evidence -> read profile -> controller tick -> orchestrator apply -> gateway sync
```

## Runtime storage

The default local runtime now persists state under `data/runtime/`:

- `bindings.json`
- `evidence.json`
- `profiles.json`
- `gateway_routes.json`

The controller asset catalog is now externalized at `data/assets/catalog.json`.
The profiler resolves tactic/technique relationships from the official MITRE
ATT&CK `attack-stix-data` bundle at `data/mitre/enterprise-attack.json`.
