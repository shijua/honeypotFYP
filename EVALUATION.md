# Evaluation Guide

This guide is the shortest path for checking the technique-informed reveal controller. It separates offline correctness from live runtime checks so you can tell whether a failure is caused by policy logic, route writing, Docker startup, or manual attacker traffic.

## 0. Prepare The Prior

The active runtime prior is generated from local Enterprise ATT&CK STIX group-technique relationships, not from raw public trace datasets.

```bash
.venv/bin/python scripts/data/fetch_mitre_attack_stix.py --output data/mitre/enterprise-attack.json
.venv/bin/python scripts/data/build_attack_group_prior.py \
  --stix data/mitre/enterprise-attack.json \
  --output data/technique_prior/attack_group_technique_prior.json
.venv/bin/python scripts/validation/attack_group_prior.py \
  --path data/technique_prior/attack_group_technique_prior.json
```

Expected: validation exits `0` and reports a non-empty group/technique prior. If the prior is missing, services can still start, but recommendation-based evaluation should be treated as degraded.

## 1. Prior Recommendation Quality

This checks whether the ATT&CK group prior recommends useful next techniques for the scripted scenario prefixes. It does not start Docker and does not open ports.

```bash
.venv/bin/python scripts/evaluation/attack_group_prior_recommendation.py \
  tests/fixtures/reveal_policy_scenarios.json \
  --prior data/technique_prior/attack_group_technique_prior.json
```

Read these fields first:

- `ok`: overall prior-evaluation status.
- `hit_rate_at_k`: share of evaluated prefixes where at least one future scenario technique appears in the top-K recommendations.
- `recall`: percentage of later scenario technique families that were recommended.
- `specificity`: percentage of not-used ATT&CK technique families that were not recommended.
- `accuracy`: percentage of ATT&CK technique families classified correctly as recommended/not recommended.
- `true_positive`, `false_positive`, `true_negative`, `false_negative`: the aggregated confusion matrix behind those metrics.
- `source_breakdown`: per-scenario confusion matrix and recall/specificity/accuracy.
- `degraded_reason`: why the prior could not be loaded, if any.

No-reveal and boundary scenarios are excluded from prior quality scoring because they test controller restraint, not next-technique recommendation. This evaluator matches sub-techniques by parent ATT&CK technique family by default, for example `T1548.003` counts as a hit when `T1548` is recommended. It uses `RuntimeConfig.recommendation_top_k` and `RuntimeConfig.recommendation_support_threshold`, whose defaults are the fixed paper parameters `K=40` and `support_threshold=0.15`; it is not a tuning sweep.

## 2. Offline Reveal Policy Replay

This is the main correctness evaluation. It replays the scenario file against multiple policies without Docker.

```bash
.venv/bin/python scripts/evaluation/reveal_policy.py \
  tests/fixtures/reveal_policy_scenarios.json \
  --policy all \
  --output /tmp/reveal_policy_report.json
```

Policies compared:

- `passive`: never reveal.
- `all-open`: reveal every eligible asset.
- `random-eligible`: random eligible baseline.
- `gate-only`: dependency gate without technique prior ranking.
- `top-recommendation`: strongest prior recommendation only.
- `controller`: current controller policy.

For the controller row, check:

- `reveal_correctness`: expected reasonable assets were opened.
- `irrelevant_reveal_rate`: opened assets outside the scenario expectation.
- `hidden_violation_rate`: opened assets that should stay hidden.
- `correct_no_reveal_rate`: scanner/boundary no-reveal cases stayed closed.
- `opened_asset_count`: average number of reveals per scenario.
- `prior_influence_rate`: how often the group prior influenced selection.
- `decision_trace_completeness`: decision details include the required audit fields.

Quick summary:

```bash
jq '.ok, .policies.controller.metrics' /tmp/reveal_policy_report.json
```

Expected: `ok=true`, no hidden violations, and no-reveal scenarios pass.

## 3. Controller-Only Port Reveal

This validates that scenario evidence causes the controller to select assets whose fixed ports match the expected route plan. It still does not start Docker.

```bash
.venv/bin/python scripts/evaluation/reveal_port_simulation.py \
  --mode controller-only \
  --scenario-file tests/fixtures/reveal_port_scenarios.json \
  --output /tmp/reveal_port_controller_report.json
```

Quick summary:

```bash
jq '.ok, .summary' /tmp/reveal_port_controller_report.json
```

Expected: `ok=true` and all default scenarios pass. This is the fastest way to check “will the right asset and port be selected?”

## 4. Live Port Reveal

This starts or uses the running compose stack, applies unlock actions, and checks the actual asset-gateway route table. It mutates `data/runtime/*.json`.

Start clean:

```bash
./scripts/reset_enterprise_runtime.sh
./scripts/start_enterprise_stack.sh
```

Run the live route check:

```bash
.venv/bin/python scripts/evaluation/reveal_port_simulation.py \
  --mode live-apply \
  --scenario-file tests/fixtures/reveal_port_scenarios.json \
  --output data/runtime/reveal_port_simulation_report.json
```

Inspect the result:

```bash
jq '.summary, .scenarios[] | {scenario_id, ok, selected_assets, expected_routes, actual_routes, failure_reason}' \
  data/runtime/reveal_port_simulation_report.json
```

Expected: each scenario has the expected `attacker_key + asset_id + public_port` route. A failure here can mean controller selection is wrong, Docker runtime startup failed, or the asset-gateway route table was not updated.

## 5. Live Runtime Latency

This measures control-plane overhead after the compose stack is running.

```bash
.venv/bin/python scripts/evaluation/runtime_latency.py \
  --assets internal-portal,finance-share,web-admin-console,ics-plc,vpn-appliance,malware-sink
```

Use a small smoke set when iterating:

```bash
.venv/bin/python scripts/evaluation/runtime_latency.py \
  --assets internal-portal,finance-share
```

Reported timings:

- binding resolve latency
- orchestrator apply latency
- runtime startup as observed by the orchestrator response
- route visible latency in `data/runtime/asset_gateway_routes.json`
- per-asset pass/fail plus min/p50/max

## 6. Manual Smoke

Use `ATTACK_TESTING_GUIDE.md` when you want to drive the attacker behavior yourself through browser, curl, SSH, or protocol probes. Keep dataset conversion and evaluation internals out of that file.

Useful validation commands after a manual run:

```bash
.venv/bin/python scripts/validation/asset_telemetry.py --require-observed
.venv/bin/python scripts/validation/high_interaction_assets.py --require-observed
.venv/bin/python scripts/reports/cowrie_commands.py --write-report data/runtime/cowrie_command_coverage.json
```

## Recommended Full Local Evaluation

For a normal development check, run this sequence:

```bash
.venv/bin/python scripts/validation/attack_group_prior.py --path data/technique_prior/attack_group_technique_prior.json
.venv/bin/python scripts/evaluation/attack_group_prior_recommendation.py tests/fixtures/reveal_policy_scenarios.json --prior data/technique_prior/attack_group_technique_prior.json
.venv/bin/python scripts/evaluation/reveal_policy.py tests/fixtures/reveal_policy_scenarios.json --policy all --output /tmp/reveal_policy_report.json
.venv/bin/python scripts/evaluation/reveal_port_simulation.py --mode controller-only --scenario-file tests/fixtures/reveal_port_scenarios.json --output /tmp/reveal_port_controller_report.json
docker-compose -p honeynet -f docker-compose.control.yml -f docker-compose.enterprise.yml config
```

Then run live-apply and latency only when Docker images and ports are available.
