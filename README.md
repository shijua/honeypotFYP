# Dynamic Honeynet (Python Monorepo)

This repository implements a profiling-driven dynamic honeynet MVP with independently testable services.

- `services/binding_service`
- `services/profiler`
- `services/controller`
- `services/orchestrator`
- `libs/contracts`
- `libs/common`

Planned but not implemented yet:

- `services/gateway`
- `services/attack_graph`

## Setup

```bash
python3.10 -m pip install -e ".[dev]"
```

The repository target is Python `3.10+`.

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
- `uvicorn services.orchestrator.app:app --reload`

Current MVP flow:

```bash
resolve binding -> ingest evidence -> read profile -> controller tick -> orchestrator apply
```
