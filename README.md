# Dynamic Honeynet (Python Monorepo)

This repository implements a profiling-driven dynamic honeynet with independently testable modules:

- `services/gateway`
- `services/binding_service`
- `services/orchestrator`
- `services/profiler`
- `services/controller`
- `services/attack_graph`
- `libs/contracts`
- `libs/common`

## Setup

```bash
pip install -e ".[dev]"
```

## Test gates

```bash
pytest -m unit
pytest -m component
pytest -m contract
pytest -m e2e_smoke
pytest -m adapter
```

## Service entrypoints

Each service has a FastAPI app object in `services/*/app.py`.
Run any service via:

```bash
uvicorn services.binding_service.app:app --reload
```
