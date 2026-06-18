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
  tests/fixtures/reveal_policy_main_scenarios.json \
  tests/fixtures/reveal_policy_scenarios.json \
  --prior data/technique_prior/attack_group_technique_prior.json \
  --output results/attack_group_prior_report.json
```

Read these fields first:

- `ok`: overall prior-evaluation status.
- `hit_rate_at_k`: share of evaluated prefixes where at least one future scenario technique appears in the prior recommendations.
- `k_sweep`: `hit_rate_at_k`, `precision`, `recall`, `mrr`, and average emitted recommendation count when varying the number of similar ATT&CK groups used by the prior.
- `precision`: percentage of recommended technique families that later appeared in the trace. This is included in JSON reports but not shown in the summary chart.
- `recall`: percentage of later scenario technique families that were recommended.
- `mrr`: mean reciprocal rank of the first future technique family that appeared in the ordered recommendations.
- `specificity` / `accuracy`: retained in JSON for completeness, but not used as headline metrics because the ATT&CK family universe is dominated by true negatives.
<!-- - `true_positive`, `false_positive`, `true_negative`, `false_negative`: the aggregated confusion matrix behind those metrics. -->
- `source_breakdown`: per-scenario confusion matrix and recall/specificity/accuracy.
- `degraded_reason`: why the prior could not be loaded, if any.

No-reveal and boundary scenarios are excluded from prior quality scoring because they test controller restraint, not next-technique recommendation. The command loads both the main full-process fixture and the broader regression fixture, so the report's `scenario_files` field states the in-domain scenario sources used. This evaluator matches sub-techniques by parent ATT&CK technique family by default, for example `T1548.003` counts as a hit when `T1548` is recommended. `RuntimeConfig.recommendation_top_k` is the number of similar ATT&CK groups used by the collaborative-filtering prior, not a cap on emitted techniques. The runtime default remains neighbor `K=40` and `support_threshold=0.15`; the `k_sweep` field is a sensitivity check over that neighbor count.

This also writes `results/attack_group_prior_report.png`, a matplotlib summary of overall prior quality and per-scenario recall.

## 2. Offline Reveal Policy Replay

This is the main correctness evaluation. It replays the scenario file against multiple policies without Docker.

```bash
.venv/bin/python scripts/evaluation/reveal_policy.py \
  tests/fixtures/reveal_policy_main_scenarios.json \
  --policy all \
  --replay-mode sequence \
  --output results/reveal_policy_main_report.json
```

This also writes `results/reveal_policy_main_report.png`, a compact visual comparison of policy metrics. The PNG path is always the JSON output path with a `.png` suffix.
The sequence mode runs each rich scenario timeline step-by-step with cumulative profile and exposure state. The main fixture uses anchor steps for exact checks and uses `anchor_step_correctness_rate` as the headline result; non-anchor steps still accumulate evidence and state but do not fail exact-step accuracy unless they open hidden/forbidden assets. Source grounding and replay semantics are documented in `tests/fixtures/README.md`.

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
- `gate-only`: the controller policy with the ATT&CK prior-support term disabled; hard gates, expected-gain ordering, explore handling, and tie-breaks remain controller-owned.
- `top-recommendation`: strongest prior recommendation only.
- `controller`: current controller policy.

The main fixture is the headline replay result and uses `anchor_step_correctness_rate` for the quality panel. The broad regression fixture is a supporting/debugging fixture; because it does not declare anchor steps, its chart quality panel falls back to `reveal_correctness` plus `hidden_violation_rate`. Do not average these two charts into one headline score: they answer different questions.

For the controller row, check:

- `reveal_correctness`: scenario-supported assets were opened.
- `irrelevant_reveal_rate`: opened assets outside the scenario expectation.
- `hidden_violation_rate`: opened assets that should stay hidden.
- `expected_reveal_match_rate`: expected `unlock` vs `configure` action types matched.
- `unexpected_reveal_action_rate`: extra `unlock` or `configure` actions not listed in `expected_reveals` or `allowed_reveals`.
- `strict_expected_reveal_match_rate`: expected actions matched and no unexpected actions were emitted.
- `configuration_reveal_count`: per-row count showing when the controller changed a configuration instead of opening a new asset.
- `correct_no_reveal_rate`: scanner/boundary no-reveal cases stayed closed.
- `anchor_step_correctness_rate`: exact reveal/no-reveal correctness on the declared key decision points only.
- `useful_evidence_per_reveal`: opened assets that the scenario marks as producing concrete useful follow-up evidence, divided by opened assets.
- `diagnostic_or_useful_per_reveal`: opened assets that the scenario marks as either useful or diagnostically informative, divided by opened assets.
- `choice_signal_count` / `resolved_choice_rate`: among controller rows with both main and explore reveals plus fixture `touched_assets`, how often follow-up behavior identified a local choice signal.
- `step_no_reveal_correctness_rate`: no-reveal expectations checked at individual timeline steps.
- `timeline_reveal_efficiency_avg`: average per-scenario touched revealed assets divided by total revealed assets.
- `source_traceability_declared_rate`: whether each timeline step declares source reference and exactness level.
- `opened_asset_count` / `avg_opened_assets`: total opened assets and average reveals per scenario.
- `gate_narrowing_rate`: average fraction of trace-visible reveal options removed by the hard dependency/readiness/signal gate before ranking. One asset unlock and one configuration variant each count as one reveal option.
- `gate_reveal_decision_space_avg` / `gate_eligible_reveal_options_avg`: average combined reveal-option count before and after the gate.
- `gate_eligible_bucket_counts`: decision-point count where the gate left `zero`, `one`, or `two_plus` eligible reveal options.
- `rejection_reason_counts`: why assets were rejected before ranking, grouped into stable categories such as missing dependency, already revealed, unavailable, or no matching signal.
- `prior_influence_rate`: how often the controller selection differs from the gate-only baseline at decision-step level, showing when the group prior changes an individual reveal decision.
- `decision_trace_completeness`: decision details include the required audit fields.

Quick summary:

```bash
jq '{ok: .ok, controller: (.policies.controller | {scenario_count, step_count, anchor_step_count, anchor_step_correctness_rate, anchor_missing_expected_reveal_count, anchor_failed_no_reveal_count, reveal_correctness, irrelevant_reveal_rate, hidden_violation_rate, correct_no_reveal_rate, step_no_reveal_correctness_rate, avg_opened_assets, useful_evidence_per_reveal, timeline_reveal_efficiency_avg, diagnostic_or_useful_per_reveal, gate_narrowing_rate, gate_reveal_decision_space_avg, gate_eligible_reveal_options_avg, gate_eligible_bucket_counts, rejection_reason_counts, prior_influenced_step_count, prior_comparison_step_count, prior_influence_rate, decision_trace_completeness_rate, source_traceability_declared_rate, choice_signal_count, resolved_choice_rate, choice_signal_counts})}' results/reveal_policy_main_report.json
```

To print the Markdown tables used for report prose, including the gate-narrowing, rejection-reason, prior-influence, and audit checks that are not plotted as separate figures:

```bash
.venv/bin/python scripts/evaluation/reveal_policy_report_summary.py \
  results/reveal_policy_main_report.json \
  results/reveal_policy_regression_report.json
```

Expected for an accepted main controller/scenario set: no hidden violations, no missing or unexpected actions on anchor steps, no failed anchor no-reveal checks, and declared source traceability for every step. The broad regression fixture may report unexpected actions when the controller opens scenario-supported assets beyond the small exact list; that is useful for debugging but is not the headline accuracy number.

## 3. Public Dataset Prior Validation

This checks whether the active ATT&CK group prior can recommend future technique families from locally downloaded ATT&CK-labelled public dataset traces. It does not train a new prior and does not affect runtime controller behavior. The reported command is scoped to CasinoLimit, and the report's `dataset_sources` field states which dataset actually contributed ordered multi-technique traces. CasinoLimit provides labelled event traces, not Enterprise ATT&CK intrusion-set-to-technique relationships.

The README setup downloads CasinoLimit into `vendor/datasets/casinolimit`. If that directory has been removed, rerun `.venv/bin/python scripts/data/fetch_public_attack_datasets.py --dataset casinolimit`.

Run the offline dataset validation:

```bash
.venv/bin/python scripts/evaluation/public_dataset_prior_validation.py \
  vendor/datasets/casinolimit \
  --prior data/technique_prior/attack_group_technique_prior.json \
  --output results/public_dataset_prior_validation_report.json
```

Expected: `trace_count > 0` when labelled local datasets exist. The report includes `dataset_sources` so the run states which datasets actually contributed traces. The script scans CSV, JSON, JSONL, YAML, and ZIP files for ordered ATT&CK technique traces, then reports the same family-aware Hit/Precision/Recall/MRR rank sweep used by scenario prior evaluation. It also reports `dataset_diagnostics`, including unique technique-family count, top-family concentration, and overlap with the prior's technique universe, so high prior scores can be interpreted against dataset diversity rather than treated as standalone generalisation evidence. It skips raw files larger than 2 MB by default; raise `--max-file-bytes` only when you specifically want to scan larger logs. A low score means the active group prior does not explain those public traces well; it does not mean the live honeynet route path is broken.

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

This measures reveal-application overhead after the compose stack is running. It is a feasibility and believability check, not a reveal-correctness metric. The report separates direct unlocks, prewarmed unlocks, and cold-start unlocks because averaging hidden prewarm, route refresh, and container startup hides the main fingerprinting risk.

```bash
.venv/bin/python scripts/evaluation/runtime_latency.py \
  --assets internal-portal,finance-share,web-admin-console,vpn-appliance,malware-sink,admin-jumpbox,dionaea-capture,honeytrap-generic \
  --runs 10 \
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

These are fixed-port Docker-backed internal surfaces that can be started hidden and later exposed by writing an asset-gateway route. They are not hot routes: warm-standby does not make the port attacker-visible until a reveal action occurs. For warm-eligible assets, the latency script records both `direct` samples, where unlock starts or refreshes the runtime, and `prewarmed` samples, where `/v1/orchestration/prewarm` starts the hidden backend before the measured reveal. Multi-run latency samples use generated attacker keys and, by default, remove the previous generated binding/runtime containers before the next sample so Docker startup variance from stale latency containers does not accumulate. Protocol or capture-heavy assets such as `admin-jumpbox`, `dionaea-capture`, and `honeytrap-generic` are not warmed by default. They should be read as the cold-start path: a reveal may include container startup or a heavier target-runtime switch, so p50/p95 latency is more important than a single best-case number.

Reported timings:

- binding resolve latency
- orchestrator apply latency
- runtime startup as observed by the orchestrator response
- hidden prewarm setup time in `binding_samples[].prewarm_apply_ms`
- route-state readiness as a pass/fail guard, not as a latency metric
- per-asset pass/fail plus apply min/p50/p95/max
- warm/cold summaries in `class_summary`, direct/prewarmed summaries in `mode_summary`, and the main comparison paths in `path_summary`

This also writes `results/runtime_latency_report.png`, showing orchestrator apply p50/p90 by asset and reveal mode in one chart. In the report, use the JSON `path_summary` for the headline warm-direct, warm-prewarmed, and cold-direct comparison; use `asset_summary` only when per-asset detail is useful. The route table check is deliberately not plotted: it confirms that the gateway state was written, but it is not the same as measuring an attacker request reaching a backend. Startup verification is part of the orchestrator apply window: after `docker run`, the runtime checks that the container is still `Up` and, when configured, healthcheck-ready before recording it as running. If cold-start latency is visibly higher, discuss it as a known content/routing observability window rather than folding it into the reveal-policy accuracy result.

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
.venv/bin/python scripts/evaluation/attack_group_prior_recommendation.py tests/fixtures/reveal_policy_main_scenarios.json tests/fixtures/reveal_policy_scenarios.json --prior data/technique_prior/attack_group_technique_prior.json --output results/attack_group_prior_report.json
.venv/bin/python scripts/evaluation/public_dataset_prior_validation.py vendor/datasets/casinolimit --prior data/technique_prior/attack_group_technique_prior.json --output results/public_dataset_prior_validation_report.json
.venv/bin/python scripts/evaluation/reveal_policy.py tests/fixtures/reveal_policy_main_scenarios.json --policy all --replay-mode sequence --output results/reveal_policy_main_report.json
.venv/bin/python scripts/evaluation/reveal_policy.py tests/fixtures/reveal_policy_scenarios.json --policy all --replay-mode sequence --output results/reveal_policy_regression_report.json
.venv/bin/python scripts/evaluation/runtime_latency.py --assets internal-portal,finance-share,web-admin-console,vpn-appliance,malware-sink,admin-jumpbox,dionaea-capture,honeytrap-generic --runs 10 --output results/runtime_latency_report.json
# Optional route-selection sanity check, not attacker-behaviour evaluation.
.venv/bin/python scripts/evaluation/reveal_port_simulation.py --mode controller-only --scenario-file tests/fixtures/reveal_port_scenarios.json --output results/reveal_port_controller_report.json
docker-compose -p honeynet -f docker-compose.control.yml -f docker-compose.enterprise.yml config
```

Plot-producing evaluation commands write the JSON report plus a sibling matplotlib SVG with the same filename stem. The route simulation command writes JSON only because it is an engineering route check and the pass/fail chart duplicates the report summary.

Then run live-apply and latency only when Docker images and ports are available.
