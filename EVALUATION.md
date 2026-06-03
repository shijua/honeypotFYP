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
  --prior data/technique_prior/attack_group_technique_prior.json \
  --output results/attack_group_prior_report.json
```

Read these fields first:

- `ok`: overall prior-evaluation status.
- `hit_rate_at_k`: share of evaluated prefixes where at least one future scenario technique appears in the top-K recommendations.
- `precision`: percentage of recommended technique families that later appeared in the trace. This is included in JSON reports but not shown in the summary chart.
- `recall`: percentage of later scenario technique families that were recommended.
- `specificity`: percentage of not-used ATT&CK technique families that were not recommended.
- `accuracy`: percentage of ATT&CK technique families classified correctly as recommended/not recommended.
<!-- - `true_positive`, `false_positive`, `true_negative`, `false_negative`: the aggregated confusion matrix behind those metrics. -->
- `source_breakdown`: per-scenario confusion matrix and recall/specificity/accuracy.
- `degraded_reason`: why the prior could not be loaded, if any.

No-reveal and boundary scenarios are excluded from prior quality scoring because they test controller restraint, not next-technique recommendation. This evaluator matches sub-techniques by parent ATT&CK technique family by default, for example `T1548.003` counts as a hit when `T1548` is recommended. It uses `RuntimeConfig.recommendation_top_k` and `RuntimeConfig.recommendation_support_threshold`, whose defaults are the fixed paper parameters `K=40` and `support_threshold=0.15`; it is not a tuning sweep.

This also writes `results/attack_group_prior_report.svg`, a matplotlib summary of overall prior quality and per-scenario recall.

## 2. Offline Reveal Policy Replay

This is the main correctness evaluation. It replays the scenario file against multiple policies without Docker.

```bash
.venv/bin/python scripts/evaluation/reveal_policy.py \
  tests/fixtures/reveal_policy_main_scenarios.json \
  --policy all \
  --replay-mode sequence \
  --output results/reveal_policy_main_report.json
```

This also writes `results/reveal_policy_main_report.svg`, a compact visual comparison of policy metrics. The SVG path is always the JSON output path with a `.svg` suffix.
The sequence mode runs each rich scenario timeline step-by-step with cumulative profile and exposure state. The main fixture uses anchor steps for exact checks and final scenario outcome for the headline result; non-anchor steps still accumulate evidence and state but do not fail exact-step accuracy unless they open hidden/forbidden assets. Source grounding and replay semantics are documented in `tests/fixtures/SCENARIO_SOURCE_TRACEABILITY.md` and `tests/fixtures/FULL_REPLAY_SCENARIO_DESIGN.md`.

The broader regression fixture is still useful for debugging edge cases. It may exit non-zero when it finds controller/scenario alignment issues; inspect the JSON rather than treating it as the headline acceptance check.

```bash
# Optional broad regression check.
.venv/bin/python scripts/evaluation/reveal_policy.py \
  tests/fixtures/reveal_policy_scenarios.json \
  --policy all \
  --replay-mode sequence \
  --output results/reveal_policy_regression_report.json
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
- `expected_reveal_match_rate`: expected `unlock` vs `configure` action types matched.
- `unexpected_reveal_action_rate`: extra `unlock` or `configure` actions not listed in `expected_reveals` or `allowed_reveals`.
- `strict_expected_reveal_match_rate`: expected actions matched and no unexpected actions were emitted.
- `configuration_reveal_count`: per-row count showing when the controller changed a configuration instead of opening a new asset.
- `correct_no_reveal_rate`: scanner/boundary no-reveal cases stayed closed.
- `anchor_step_correctness_rate`: exact reveal/no-reveal correctness on the declared key decision points only.
- `final_outcome_success_rate`: full scenario replay reached the declared final useful/reasonable outcome.
- `useful_evidence_per_reveal`: opened assets that the scenario marks as producing concrete useful follow-up evidence, divided by opened assets.
- `diagnostic_or_useful_per_reveal`: opened assets that the scenario marks as either useful or diagnostically informative, divided by opened assets.
- `choice_signal_count` / `resolved_choice_rate`: among controller rows with both main and explore reveals plus fixture `touched_assets`, how often follow-up behavior identified a local choice signal.
- `step_no_reveal_correctness_rate`: no-reveal expectations checked at individual timeline steps.
- `timeline_reveal_efficiency_avg`: average per-scenario touched revealed assets divided by total revealed assets.
- `source_traceability_declared_rate`: whether each timeline step declares source reference and exactness level.
- `opened_asset_count` / `avg_opened_assets`: total opened assets and average reveals per scenario.
- `gate_narrowing_rate`: average fraction of considered assets removed by the hard dependency/readiness/signal gate before ranking.
- `gate_ready_assets_before_gate_avg` / `gate_eligible_assets_after_gate_avg`: average candidate count before and after the gate.
- `gate_eligible_bucket_counts`: decision-point count where the gate left `zero`, `one`, or `two_plus` eligible candidates.
- `rejection_reason_counts`: why assets were rejected before ranking, grouped into stable categories such as missing dependency, already revealed, unavailable, or no matching signal.
- `prior_influence_rate`: how often the controller selection differs from the gate-only baseline, showing when the group prior changes the reveal decision.
- `decision_trace_completeness`: decision details include the required audit fields.

Quick summary:

```bash
jq '{ok: .ok, controller: (.policies.controller | {scenario_count, step_count, anchor_step_count, anchor_step_correctness_rate, anchor_missing_expected_reveal_count, anchor_failed_no_reveal_count, final_outcome_success_rate, reveal_correctness, irrelevant_reveal_rate, hidden_violation_rate, correct_no_reveal_rate, step_no_reveal_correctness_rate, avg_opened_assets, useful_evidence_per_reveal, timeline_reveal_efficiency_avg, diagnostic_or_useful_per_reveal, gate_narrowing_rate, gate_ready_assets_before_gate_avg, gate_eligible_assets_after_gate_avg, gate_eligible_bucket_counts, rejection_reason_counts, prior_influence_rate, decision_trace_completeness_rate, source_traceability_declared_rate, choice_signal_count, resolved_choice_rate, choice_signal_counts})}' results/reveal_policy_main_report.json
```

Expected for an accepted main controller/scenario set: no hidden violations, no missing or unexpected actions on anchor steps, no failed anchor no-reveal checks, declared source traceability for every step, and successful final useful/reasonable outcomes. The broad regression fixture may report unexpected actions when the controller reasonably opens more than a small scenario listed; that is useful for debugging but is not the headline accuracy number.

## 3. Optional Public Dataset Prior Validation

This checks whether the active ATT&CK group prior can recommend future technique families from locally downloaded ATT&CK-labelled public dataset traces. It does not train a new prior and does not affect runtime controller behavior. The reported command is scoped to CasinoLimit and UWF-ZeekData24 paths, and the report's `dataset_sources` field states which of those datasets actually contributed ordered multi-technique traces. These datasets provide labelled event traces, not Enterprise ATT&CK intrusion-set-to-technique relationships.

Fetch optional validation material only when needed:

```bash
.venv/bin/python scripts/data/fetch_public_attack_datasets.py --dry-run
.venv/bin/python scripts/data/fetch_public_attack_datasets.py --dataset uwf-zeekdata24
.venv/bin/python scripts/data/fetch_public_attack_datasets.py --dataset casinolimit
```

Run the offline dataset validation:

```bash
.venv/bin/python scripts/evaluation/public_dataset_prior_validation.py \
  vendor/datasets/casinolimit \
  vendor/datasets/uwf-zeekdata24 \
  --prior data/technique_prior/attack_group_technique_prior.json \
  --output results/public_dataset_prior_validation_report.json
```

Expected: `trace_count > 0` when labelled local datasets exist. The report includes `dataset_sources` so the run states which datasets actually contributed traces. The script scans CSV, JSON, JSONL, YAML, and ZIP files for ordered ATT&CK technique traces, then reports the same family-aware precision, recall, specificity, and accuracy metrics used by scenario prior evaluation. It skips raw files larger than 2 MB by default; raise `--max-file-bytes` only when you specifically want to scan larger logs. A low score means the active group prior does not explain those public traces well; it does not mean the live honeynet route path is broken.

## 4. Optional Controller-Only Route Check

This is an engineering check for route selection, not a headline behaviour metric. It validates that scenario evidence causes the controller to select assets whose fixed ports match the expected route plan. It still does not start Docker.

```bash
.venv/bin/python scripts/evaluation/reveal_port_simulation.py \
  --mode controller-only \
  --scenario-file tests/fixtures/reveal_port_scenarios.json \
  --output results/reveal_port_controller_report.json
```

Quick summary:

```bash
jq '.ok, .summary' results/reveal_port_controller_report.json
```

Expected: `ok=true` and all default scenarios pass. This is the fastest way to check “will the right asset, action type, and port be selected?” Configuration scenarios show `selected_actions[].action_type == "configure"` and include `configuration_id`.

This command writes JSON only. Route-check failures are easier to inspect from `summary`, `failure_reason`, `expected_routes`, and `actual_routes` than from a pass/fail chart.

## 5. Optional Live Route Check

This starts or uses the running compose stack, applies unlock actions, and checks the actual asset-gateway route table. It mutates `data/runtime/*.json`. Use it to debug the controller -> orchestrator -> gateway path. Use manual traffic checks for attacker-visible behaviour and technique evidence.

Important boundary: `live-apply` does not run attacker commands, browser clicks, curl probes, SSH sessions, FTP transfers, or shell commands. It validates the control-plane and data-plane route result: controller selection -> orchestrator apply -> Docker runtime -> `asset_gateway_routes.json`. Use `ATTACK_TESTING_GUIDE.md` after this when you need to verify real attacker traffic and ATT&CK evidence.

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
jq '.summary, .scenarios[] | {scenario_id, ok, selected_assets, selected_actions, expected_routes, actual_routes, failure_reason}' \
  data/runtime/reveal_port_simulation_report.json
```

Expected: each scenario has the expected `attacker_key + asset_id + public_port` route. A failure here can mean controller selection is wrong, Docker runtime startup failed, or the asset-gateway route table was not updated. A pass here only means the route is open; it does not prove the backend generated telemetry.

## 6. Live Runtime Latency

This measures control-plane overhead after the compose stack is running.

```bash
.venv/bin/python scripts/evaluation/runtime_latency.py \
  --assets internal-portal,finance-share,web-admin-console,vpn-appliance,malware-sink \
  --output results/runtime_latency_report.json
```

Warm-standby is catalog-owned. The assets currently marked as warm-standby eligible are:

| Asset | Gateway port |
| --- | --- |
| `internal-portal` | `18080` |
| `finance-share` | `18082` |
| `git-internal` | `19418` |
| `ops-db` | `13306` |
| `redis-cache` | `16379` |
| `web-admin-console` | `18081` |
| `ftp-archive` | `12121` |
| `ssh-canary` | `12222` |
| `vpn-appliance` | `18443` |
| `malware-sink` | `18085` |

These are fixed-port Docker-backed internal surfaces that can be started hidden and later exposed by writing an asset-gateway route. They are not hot routes: warm-standby does not make the port attacker-visible until a reveal action occurs. Protocol or capture-heavy assets such as `admin-jumpbox`, `legacy-telnet`, `mail-relay`, `dionaea-capture`, and `honeytrap-generic` are not warmed by default.

Reported timings:

- binding resolve latency
- orchestrator apply latency
- runtime startup as observed by the orchestrator response
- route visible latency in `data/runtime/asset_gateway_routes.json`
- per-asset pass/fail plus min/p50/max

This also writes `results/runtime_latency_report.svg`, showing orchestrator apply time and route-visible time by asset.

## 7. Manual Smoke

Use `ATTACK_TESTING_GUIDE.md` when you want to drive attacker behavior yourself through browser, curl, SSH, FTP, SMTP, Redis, MySQL, Dionaea, or generic TCP probes. Keep dataset conversion and evaluation internals out of that file.

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
.venv/bin/python scripts/evaluation/attack_group_prior_recommendation.py tests/fixtures/reveal_policy_scenarios.json --prior data/technique_prior/attack_group_technique_prior.json --output results/attack_group_prior_report.json
.venv/bin/python scripts/evaluation/reveal_policy.py tests/fixtures/reveal_policy_main_scenarios.json --policy all --replay-mode sequence --output results/reveal_policy_main_report.json
.venv/bin/python scripts/evaluation/reveal_policy.py tests/fixtures/reveal_policy_scenarios.json --policy all --replay-mode sequence --output results/reveal_policy_regression_report.json || true
# Optional route-selection sanity check, not attacker-behaviour evaluation.
.venv/bin/python scripts/evaluation/reveal_port_simulation.py --mode controller-only --scenario-file tests/fixtures/reveal_port_scenarios.json --output results/reveal_port_controller_report.json
docker-compose -p honeynet -f docker-compose.control.yml -f docker-compose.enterprise.yml config
```

Plot-producing evaluation commands write the JSON report plus a sibling matplotlib SVG with the same filename stem. The route simulation command writes JSON only because it is an engineering route check and the pass/fail chart duplicates the report summary.

Then run live-apply and latency only when Docker images and ports are available.
