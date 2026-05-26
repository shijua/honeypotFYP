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
python scripts/data/fetch_mitre_attack_stix.py
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
Public HTTP/Cowrie/OpenCanary evidence -> resolve binding -> ingest evidence -> read profile -> controller tick -> orchestrator apply -> gateway sync
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
- `asset_gateway_routes.json`

The controller asset catalog is now externalized at `data/assets/catalog.json`. Public HTTP profiling uses Sigma YAML rules in `data/detections/http_sigma`; only matching suspicious public-web requests create profiler evidence. Cowrie event mappings are externalized at `data/cowrie/event_mappings.json`. The profiler resolves tactic/technique relationships from the official MITRE ATT&CK `attack-stix-data` bundle at `data/mitre/enterprise-attack.json`.

## ATT&CK Group Technique Prior

The controller uses an ATT&CK group-technique prior as a ranking signal. The prior is not an asset mapping. It estimates plausible adjacent techniques from public ATT&CK group knowledge, while `data/assets/catalog.json` decides which honeypot asset can plausibly cover each technique and which dependency signals are required.

The repo expects optional public raw datasets under ignored `vendor/datasets/`. These datasets are validation material, not the active runtime prior. You can keep the default location or pass `--output-root /path/to/datasets` to the fetcher.

```bash
vendor/datasets/mordor/
vendor/datasets/casinolimit/
vendor/datasets/uwf-zeekdata24/
```

For a practical validation-data run, fetch the three supported public sources. UWF-ZeekData24 and CasinoLimit are fetched by the default command. Mordor/OTRF is supported through GitHub metadata plus metadata-declared zip files, including Host, Network, and Cloud entries.

```bash
python scripts/data/fetch_public_attack_datasets.py
```

Add a small Mordor/OTRF sample explicitly:

```bash
python scripts/data/fetch_public_attack_datasets.py --dataset mordor --mordor-section compound --mordor-limit 20
```

Fetch all Mordor/OTRF metadata-declared zip entries:

```bash
python scripts/data/fetch_public_attack_datasets.py --dataset mordor --mordor-limit 0
```

Use `--mordor-file-type host` if you want only Host zip entries for a lighter local checkout.

Build the ATT&CK group-technique collaborative-filtering prior from the local Enterprise ATT&CK STIX bundle:

```bash
python scripts/data/build_attack_group_prior.py \
  --stix data/mitre/enterprise-attack.json \
  --output data/technique_prior/attack_group_technique_prior.json
python scripts/validation/attack_group_prior.py
```

`data/technique_prior/attack_group_technique_prior.json` is generated local state and is ignored by git. The builder reads `intrusion-set --uses--> attack-pattern` relationships and does not infer missing labels. If the file is missing, the controller still starts but dashboard health marks the group prior as degraded and recommendations fall back to observed-technique continuation only.

Use `python scripts/data/fetch_public_attack_datasets.py --dry-run` to inspect optional public datasets for later validation work. Use `--dataset uwf-zeekdata24`, `--dataset casinolimit`, or `--dataset mordor` to fetch one source under ignored `vendor/datasets/`. Those raw datasets are not the active runtime prior; they are kept for offline comparison and future validation experiments.

## Cowrie Command Detection

Cowrie command profiling has three runtime modes:

| Mode | Runtime catalog | Purpose |
| --- | --- | --- |
| `local` | `data/cowrie/command_mapping_rules.json` | Project-owned command mappings for known honeypot behaviors |
| `sigma` | `data/detections/cowrie_sigma:vendor/sigma/rules/linux` | Project-owned Sigma rules plus optional external Linux Sigma rules that can be expressed from Cowrie commands |
| `hybrid` | local catalog, then runtime Sigma catalog | Practical mode that keeps project-specific coverage while adding Sigma coverage |

The default mode is `hybrid`, using the local mapping file plus repo-owned Sigma rules and `vendor/sigma/rules/linux` when that optional checkout exists. To test an external SigmaHQ checkout, fetch it or point `HONEYPOT_COWRIE_SIGMA_RULES_PATH` at one or more rule directories separated by `:`.

```bash
mkdir -p vendor
test -d vendor/sigma || git clone --depth 1 https://github.com/SigmaHQ/sigma.git vendor/sigma
```

Run the stack with the desired mode:

```bash
# default hybrid command detection
./scripts/start_enterprise_stack.sh
HONEYPOT_COWRIE_COMMAND_MAPPING_MODE=sigma ./scripts/start_enterprise_stack.sh
HONEYPOT_COWRIE_SIGMA_RULES_PATH=data/detections/cowrie_sigma:vendor/sigma/rules/linux HONEYPOT_COWRIE_COMMAND_MAPPING_MODE=hybrid ./scripts/start_enterprise_stack.sh
```

The Cowrie adapter reads the configured Sigma YAML folder directly at runtime and imports rule conditions it can express from one Cowrie command: process/image fields, command-line fields, auditd `EXECVE` arguments, and simple keyword lists. The supported condition subset includes standalone selections, `selection_a and selection_b`, `all of selection_*`, `1 of selection_*`, and `selection and not filter_*`. Selections with unsupported fields are skipped instead of weakened. Override the Sigma rule directory with `HONEYPOT_COWRIE_SIGMA_RULES_PATH` when testing a different Sigma checkout.

Use `ATTACK_TESTING_GUIDE.md` only to test whether live Cowrie commands produce observations and profiler evidence. Rule-source details belong here and in `ARCHITECTURE.md`, not in the testing guide.

## Simulation Helpers

Useful helper scripts are kept in `scripts/` and covered by tests:

```bash
./scripts/test_enterprise_compose.sh
python scripts/validation/asset_telemetry.py --asset-id internal-portal
.venv/bin/python scripts/reports/cowrie_commands.py --write-report data/runtime/cowrie_command_coverage.json
```

The top-level shell scripts in `scripts/` are the commands you normally run by hand. Python helpers are grouped by role: `scripts/forwarders/` tails service logs into adapters, `scripts/validation/` checks asset telemetry and mappings, `scripts/reports/` builds coverage summaries, `scripts/runtime/` holds long-running control loops, and `scripts/data/` stores data-fetch utilities.

Use the manual flow in `ATTACK_TESTING_GUIDE.md` when you want to drive the attacker actions yourself.

## Enterprise Compose Draft

The enterprise-network deployment uses two compose files:

- `docker-compose.control.yml` runs the control plane.
- `docker-compose.enterprise.yml` runs the benign surface, attacker entrypoints, and currently real enterprise assets.

Set environment variables inline when local ports or bind addresses need to change. Keep `HOST_BIND_ADDRESS=127.0.0.1` for SSH-tunnel/local-only testing; use `HOST_BIND_ADDRESS=0.0.0.0` or a specific private IP if you want browser/terminal access from your LAN/VPN.

Reset old containers and runtime state before a fresh run:

```bash
./scripts/reset_enterprise_runtime.sh
```

Start the runnable stack without generating attacker traffic:

```bash
./scripts/start_enterprise_stack.sh
```

The enterprise slice includes `public-portal`, a public-portal access-log forwarder, Cowrie, the public website HTTP backend, OpenCanary telemetry plumbing, and adaptive internal assets. The public portal implements benign-surface breadcrumbs: login/support/status/API pages, `/robots.txt`, legacy backup files, `.env.old`, `phpinfo.php`, and frontend source-map credential breadcrumbs. Public portal nginx access logs are forwarded into the HTTP backend; suspicious requests are classified by `data/detections/http_sigma` and sent to the profiler.

Useful public breadcrumb probes after the stack starts:

```bash
curl -i http://$CLIENT_TARGET_HOST:${PUBLIC_PORTAL_PORT:-8080}/.env.old
curl -i http://$CLIENT_TARGET_HOST:${PUBLIC_PORTAL_PORT:-8080}/backup/db_backup_2024.sql.bak
curl -i http://$CLIENT_TARGET_HOST:${PUBLIC_PORTAL_PORT:-8080}/backup/passwords_internal.txt
curl -i http://$CLIENT_TARGET_HOST:${PUBLIC_PORTAL_PORT:-8080}/assets/app.js.map
```

Current service roles:

| Service | Layer | Host port | Purpose |
| --- | --- | --- | --- |
| `public-portal` | benign user surface | `8080` | Real-looking public site and breadcrumb files such as `/robots.txt`, `/.env.old`, and source maps |
| `public-portal-forwarder` | telemetry bridge | none | Tails public portal nginx access logs and posts them to `entrypoint-observer` |
| `entrypoint-observer` | public website backend + direct HTTP test entrypoint | `8083` | Receives public portal breadcrumbs and handles explicit low-interaction HTTP probes |
| `cowrie` | attacker-facing entrypoint | `2222` | SSH interaction and command telemetry |
| `asset-gateway` | adaptive asset data plane | `18080`, `19418`, `13306`, `16379`, `18081`, `12121`, `12222`, `12323`, `2525`, `18082`, `18443`, `18085` | Owns fixed external ports, forwards each attacker to the backend selected by source IP, and writes internal HTTP artifact events to JSONL |
| `internal-http-forwarder` | telemetry bridge | none | Tails `data/runtime/internal_http_events.jsonl` and posts internal HTTP asset events to `entrypoint-observer` |
| `opencanary-adapter` + `opencanary-forwarder` | adaptive asset telemetry | none | Collect logs from OpenCanary-backed internal assets after they are unlocked |
| `internal-portal` | internal baseline service | internal only; reached through `asset-gateway` on `18080` when dynamically unlocked | First internal asset in the adaptive path |
| `binding-service`, `profiler`, `controller`, `orchestrator`, `gateway`, `adaptive-loop`, `dashboard` | control plane | dashboard on `8090`; APIs internal | Profiling, asset selection, runtime start, route state, and live monitoring |

Adaptive internal Docker assets no longer publish host ports themselves. The orchestrator starts one backend container per binding on `net_internal`, writes `data/runtime/asset_gateway_routes.json`, and the `asset-gateway` container owns the fixed external ports. For the MVP, the data-plane gateway treats the same source IP as the same attacker and routes strictly by `attacker_key + public_port`; if the source IP has not unlocked that asset, the gateway closes the connection instead of falling back to another attacker route. For static internal HTTP assets, the gateway also extracts the first HTTP request path and appends it to `data/runtime/internal_http_events.jsonl`, marked as `surface=internal`. The separate `internal-http-forwarder` container reads that file from `net_control` and posts it into the profiler path, so the public/internal data-plane gateway does not need direct control-plane network access.

OpenCanary is no longer an always-on attacker-facing entrypoint. OpenCanary telemetry is collected through `scripts/forwarders/opencanary_json.py`, which tails `deploy/opencanary/var/opencanary.log` and posts events into `services/opencanary`. Adaptive internal OpenCanary assets mount that shared log directory, so their Git/MySQL/Redis/HTTP/FTP/SSH/Telnet events flow into the dashboard after the controller unlocks them.

The adaptive internal catalog includes standalone OpenCanary assets for Git, MySQL, Redis, FTP, SSH, and Telnet, plus lightweight static Docker assets for finance-share, VPN appliance, and malware-drop-sink services. The static assets include backup/config/archive breadcrumbs such as `.bak`, `.ovpn`, and package-download paths. They are not enabled by changing one shared OpenCanary configuration; the orchestrator starts a separate container per asset when the controller unlocks it. Default host ports can be overridden with shell environment variables:

The controller now treats public-file exploration as part of the dependency model. For example, probing `/.env.old`, `/backup/db_backup_2024.sql.bak`, `/backup/passwords_internal.txt`, `/assets/app.js.map`, `/admin`, or SQL-injection-looking API requests creates public HTTP evidence in the profile. Catalog assets can declare `default_settings.unlock_signals` so they only become eligible after the matching public path, rule, or indicator has been seen.

```bash
GIT_INTERNAL_PORT=19418
OPS_DB_PORT=13306
REDIS_CACHE_PORT=16379
WEB_ADMIN_CONSOLE_PORT=18081
FTP_ARCHIVE_PORT=12121
SSH_CANARY_PORT=12222
LEGACY_TELNET_PORT=12323
MAIL_RELAY_PORT=2525
FINANCE_SHARE_PORT=18082
VPN_APPLIANCE_PORT=18443
MALWARE_SINK_PORT=18085
ASSET_GATEWAY_PORTS=18080,19418,13306,16379,18081,12121,12222,12323,2525,18082,18443,18085
```

Static internal breadcrumb examples after the matching source IP has unlocked the relevant asset:

```bash
curl -i http://$CLIENT_TARGET_HOST:${FINANCE_SHARE_PORT:-18082}/exports/db_backup_2024.sql.bak
curl -i http://$CLIENT_TARGET_HOST:${VPN_APPLIANCE_PORT:-18443}/backup/ra-config-2026-04.bak
curl -i http://$CLIENT_TARGET_HOST:${MALWARE_SINK_PORT:-18085}/downloads/agent-update.bin
```

For manual port/page testing, `scripts/unlock_internal_assets_for_test.sh` can force-open gateway-testable internal Docker assets for one source IP through the normal orchestrator API:

```bash
ATTACKER_KEY=$CLIENT_TARGET_HOST ./scripts/unlock_internal_assets_for_test.sh
```

Validate runtime/gateway/dashboard data after opening assets:

```bash
python scripts/validation/asset_telemetry.py --require-observed
python scripts/validation/high_interaction_assets.py --require-observed
```

`asset_telemetry.py` validates runtime-enabled catalog assets, including high-interaction paths. If `admin-jumpbox` or other high-interaction assets are selected without their runtime and telemetry being present, the script reports them as missing instead of silently treating them as later-only.

Live monitoring dashboard:

```bash
TARGET_HOST=127.0.0.1
curl http://$TARGET_HOST:${DASHBOARD_PORT:-8090}/healthz
```

Then open `http://$TARGET_HOST:${DASHBOARD_PORT:-8090}/` in a browser.

The dashboard includes a Pipeline Health panel that traces the live path from public surface access logs, HTTP rule matching, Cowrie/OpenCanary forwarders, adapters, profile/controller, gateway, and dashboard state. This is the first place to look when public HTTP probes, raw Cowrie commands, OpenCanary internal asset probes, or public website backend observations do not appear in the profile view.

Manual actor check after startup:

```bash
TARGET_HOST=127.0.0.1
curl http://$TARGET_HOST:8080/
curl -i -A "sqlmap/1.8 manual-test" http://$TARGET_HOST:8083/.env
ssh -p 2222 root@$TARGET_HOST
curl http://$TARGET_HOST:18080/
```

The default compose stack includes an adaptive loop, so new public HTTP, Cowrie, or OpenCanary profile evidence can trigger controller/orchestrator asset unlocks without manually calling those APIs.
