# Dynamic Honeynet

This repository implements a technique-informed dynamic honeynet: public and SSH telemetry build an attacker profile, the controller chooses plausible internal assets or configuration changes, the orchestrator starts runtimes, and the asset gateway exposes only the selected fixed ports for that attacker.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) explains the system design, data flow, controller logic, runtime routing, and telemetry path.
- [EVALUATION.md](EVALUATION.md) explains offline policy evaluation, prior checks, controller-only port checks, live route checks, and latency measurement.
- [ATTACK_TESTING_GUIDE.md](ATTACK_TESTING_GUIDE.md) contains live/manual attacker actions: browser, curl, SSH, FTP, SMTP, Redis, MySQL, Dionaea, and generic TCP probes.

Use the testing guide when you want to simulate attacker behavior. The `live-apply` evaluation opens routes through Docker and the asset gateway, but it does not run attacker commands or protocol probes.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `services/` | Runtime services: public entrypoint, binding service, profiler, controller, orchestrator, asset gateway, dashboard, and telemetry adapters. |
| `libs/` | Shared contracts and common helpers used by multiple services and scripts. |
| `scripts/data/` | One-off data builders and fetchers, including MITRE ATT&CK STIX fetch and ATT&CK group prior generation. |
| `scripts/evaluation/` | Offline and live evaluation entry points: reveal-policy replay, prior validation, port reveal simulation, and runtime latency. |
| `scripts/runtime/` | Local runtime loops and small helper services used by the live stack. |
| `scripts/forwarders/` | Log forwarders that move honeypot/runtime logs into the service adapters. |
| `scripts/validation/` | Lightweight validators for generated priors, catalog assumptions, and runtime telemetry files. |
| `data/assets/` | Asset catalog and selection metadata used by the controller and orchestrator. |
| `data/detections/` | Project-owned Sigma-style detection rules for public/internal HTTP, Cowrie, and high-interaction telemetry. |
| `data/runtime/` | Local runtime state written by the running stack; ignored except for placeholders. |
| `data/technique_prior/` | Generated ATT&CK group technique prior used by the controller; ignored except for placeholders. |
| `deploy/` | Docker/runtime assets, static internal surfaces, public portal files, and honeypot configuration. |
| `tests/` | Unit, component, evaluation, and fixture tests. `tests/fixtures/README.md` explains scenario files. |
| `vendor/` | Optional external source material such as SigmaHQ rules and public validation datasets; ignored by git. |

## Local Generated State

A clean clone should be understandable from the tracked source, docs, tests, `data/assets/`, `data/detections/`, and `deploy/`. Ignored local outputs such as `.venv/`, `data/runtime/`, `data/mitre/`, `data/technique_prior/`, `vendor/`, `results/`, `*.egg-info/`, and root-level `infra-deploy/` can be deleted and recreated; the intentional fake internal repo seed lives under `deploy/internal-assets/git-internal/seed/infra-deploy/`.

## Setup

```bash
python3.10 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python scripts/data/fetch_mitre_attack_stix.py --output data/mitre/enterprise-attack.json
.venv/bin/python scripts/data/build_attack_group_prior.py \
  --stix data/mitre/enterprise-attack.json \
  --output data/technique_prior/attack_group_technique_prior.json
.venv/bin/python scripts/validation/attack_group_prior.py \
  --path data/technique_prior/attack_group_technique_prior.json
```

The active reveal policy reads the generated ATT&CK group-technique prior at `data/technique_prior/attack_group_technique_prior.json`. This generated file is local state and ignored by git. Raw public validation datasets, if used, belong under ignored `vendor/datasets/`.

For evaluation commands, chart generation, route checks, and latency checks, see [EVALUATION.md](EVALUATION.md).

## Live Stack

```bash
./scripts/reset_enterprise_runtime.sh
./scripts/start_enterprise_stack.sh
```

After the stack starts, use [ATTACK_TESTING_GUIDE.md](ATTACK_TESTING_GUIDE.md) for manual traffic and check the dashboard at port `8090` for profiles, decisions, routes, and asset state. Generated route-check reports, when you run them from [EVALUATION.md](EVALUATION.md), are written under `data/runtime/`.

## Optional Sigma Rule Source

Cowrie command detection still supports `local`, `sigma`, and `hybrid` via `HONEYPOT_COWRIE_COMMAND_MAPPING_MODE`. The default is `hybrid`: it loads `data/cowrie/command_mapping_rules.json` first, then compatible Sigma YAML from `data/detections/cowrie_sigma` and optional SigmaHQ Linux rules when `vendor/sigma` exists.

```bash
mkdir -p vendor
test -d vendor/sigma || git clone --depth 1 https://github.com/SigmaHQ/sigma.git vendor/sigma
```
