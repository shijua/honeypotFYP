# Dynamic Honeynet

This repository implements a technique-informed dynamic honeynet: public and SSH telemetry build an attacker profile, the controller chooses plausible internal assets or configuration changes, the orchestrator starts runtimes, and the asset gateway exposes only the selected fixed ports for that attacker.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) explains the system design, data flow, controller logic, runtime routing, and telemetry path.
- [EVALUATION.md](EVALUATION.md) explains offline policy evaluation, prior checks, controller-only port checks, live route checks, and latency measurement.
- [ATTACK_TESTING_GUIDE.md](ATTACK_TESTING_GUIDE.md) contains live/manual attacker actions: browser, curl, SSH, FTP, SMTP, Redis, MySQL, Dionaea, and generic TCP probes.

Use the testing guide when you want to simulate attacker behavior. The `live-apply` evaluation opens routes through Docker and the asset gateway, but it does not run attacker commands or protocol probes.

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

The generated prior at `data/technique_prior/attack_group_technique_prior.json` is local state and ignored by git. Raw public validation datasets, if used, belong under ignored `vendor/datasets/`.

## Fast Checks

```bash
.venv/bin/pytest tests/entrypoint/test_asset_access_to_technique_coverage.py tests/assets/test_asset_catalog_runtime.py tests/controller -q
.venv/bin/python scripts/evaluation/reveal_policy.py tests/fixtures/reveal_policy_scenarios.json --policy all --output /tmp/reveal_policy_report.json
.venv/bin/python scripts/evaluation/reveal_port_simulation.py --mode controller-only --scenario-file tests/fixtures/reveal_port_scenarios.json --output /tmp/reveal_port_controller_report.json
docker-compose -p honeynet -f docker-compose.control.yml -f docker-compose.enterprise.yml config
```

For the full evaluation sequence and chart outputs, see [EVALUATION.md](EVALUATION.md).

## Live Stack

```bash
./scripts/reset_enterprise_runtime.sh
./scripts/start_enterprise_stack.sh
```

After the stack starts, use [ATTACK_TESTING_GUIDE.md](ATTACK_TESTING_GUIDE.md) for manual traffic. If you only want to verify that the controller can open the expected Docker-backed routes, run:

```bash
.venv/bin/python scripts/evaluation/reveal_port_simulation.py \
  --mode live-apply \
  --scenario-file tests/fixtures/reveal_port_scenarios.json \
  --output data/runtime/reveal_port_simulation_report.json
```

Then inspect:

```bash
jq '.summary, .scenarios[] | {scenario_id, ok, selected_assets, selected_actions, expected_routes, actual_routes, failure_reason}' \
  data/runtime/reveal_port_simulation_report.json
```

Remember: `live-apply` validates route creation, not attacker behavior. To verify commands, HTTP paths, protocol probes, and resulting ATT&CK evidence, run the manual sections in [ATTACK_TESTING_GUIDE.md](ATTACK_TESTING_GUIDE.md).

## Optional Rule And Dataset Sources

Cowrie command detection supports local, Sigma, and hybrid modes. The default hybrid mode uses project-owned rules plus optional SigmaHQ Linux rules when `vendor/sigma` exists.

```bash
mkdir -p vendor
test -d vendor/sigma || git clone --depth 1 https://github.com/SigmaHQ/sigma.git vendor/sigma
HONEYPOT_COWRIE_SIGMA_RULES_PATH=data/detections/cowrie_sigma:vendor/sigma/rules/linux \
HONEYPOT_COWRIE_COMMAND_MAPPING_MODE=hybrid \
./scripts/start_enterprise_stack.sh
```

Optional ATT&CK-labelled public datasets can be fetched for offline validation work; they are not the active runtime prior.

```bash
.venv/bin/python scripts/data/fetch_public_attack_datasets.py --dry-run
```
