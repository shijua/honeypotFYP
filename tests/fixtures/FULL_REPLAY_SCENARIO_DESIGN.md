# Full-Process Reveal Replay Design

`reveal_policy_main_scenarios.json` is the headline full-process replay fixture. It contains fewer, richer timelines and checks exact decisions only at declared anchor steps. `reveal_policy_scenarios.json` remains a broader regression fixture for edge cases and debugging. The old snapshot replay is still supported for compatibility, but the main evaluation should use:

```bash
.venv/bin/python scripts/evaluation/reveal_policy.py tests/fixtures/reveal_policy_main_scenarios.json --policy all --replay-mode sequence --output /tmp/reveal_policy_main_report.json
```

## Replay Semantics

Each timeline step represents one controller decision point. The evaluator adds the step's `new_evidence` to the cumulative profile, runs the selected policy once, then updates simulated `unlocked_asset_ids` and `revealed_configurations` from the actions returned by that step. Later steps therefore see the assets and configuration variants opened earlier in the scenario.

This is still an offline replay. It does not start Docker, open gateway routes, or generate live attacker traffic. It answers the decision-quality question: given this sequence of attacker evidence, did the policy make the key anchor decisions correctly without exposing hidden assets?

## Step Fields

| Field | Meaning |
| --- | --- |
| `step_id` | Stable step identifier used in reports. |
| `phase` | Human-readable phase such as public exploit, discovery, follow-up, or active-path configuration. |
| `new_evidence` | Evidence records introduced at this step; these use the same compact fields as the previous `evidence_sequence`. |
| `anchor_check` | When true, this step participates in exact step correctness. Use this only for first reveal, boundary/no-reveal, response-gated wait, active-path configuration, and final useful follow-up checks. |
| `expected_reveals` | Exact unlock/configure actions expected at this step. |
| `allowed_reveals` | Extra acceptable actions when multiple equivalent catalog variants are reasonable. |
| `expected_no_reveal` | The correct action for this step is to avoid opening new exposure. |
| `expected_response_gate_wait` | A stricter no-reveal case: the policy should wait because the previous reveal has not produced a response. |
| `touched_assets` | Assets the replay says the attacker actually touched after a reveal; this is used for choice/reveal-efficiency metrics. |
| `source_refs` | Per-step source grounding. Each entry declares a reference id and an exactness level. |

## Anchor Metrics

The sequence report keeps the historical per-scenario fields and adds `timeline`, `step_count`, `anchor_step_correctness_rate`, `step_no_reveal_correctness_rate`, `response_gate_wait_correctness_rate`, `timeline_reveal_efficiency`, and `source_traceability_status`.

Only steps with `anchor_check: true` are used for exact reveal/no-reveal correctness. Non-anchor steps still accumulate evidence, update unlocked assets, and can fail the scenario if they open a hidden asset, but they do not fail exact-step accuracy just because the controller chose another reasonable asset.

The main report `ok` condition is based on no hidden violations, no missing or unexpected anchor actions, no failed anchor no-reveal checks, and declared source traceability. The broad regression fixture can still expose strict mismatch details, but those are not the headline accuracy number.

`timeline_reveal_efficiency` is intentionally simple: revealed assets that the scenario later marks as touched divided by total revealed assets. It is not an information-gain or entropy metric.

## Source Exactness Levels

| Level | Meaning |
| --- | --- |
| `direct` | The report describes the same behavior at roughly the same level of detail as the replay step. |
| `technique-level` | The source supports the ATT&CK technique or behavior family, but not this exact local path, file, or hostname. |
| `local-adaptation` | The local path, file, service, or asset is honeynet-specific and only simulates a source-backed behavior. |
| `negative-control` | The scenario is deliberately synthetic and tests no-reveal or false-positive behavior. |

## Important Limitation

The timeline is not a claim that a public report contained paths such as `/assets/app.js.map`, `/.env.old`, `/backup/passwords_internal.txt`, or `/admin`. Those are local cover-story artifacts used to emulate broader report-backed behaviors such as file discovery, credential discovery, admin surface probing, remote-service interest, and tool-transfer intent.
