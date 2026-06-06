# Evaluation Fixtures

These fixtures are intentionally split by evaluation question.

## `reveal_policy_main_scenarios.json`

Main offline policy replay. This is the headline decision-quality fixture: it uses fewer, richer full-process timelines, exact checks only at `anchor_check` steps, and final scenario outcomes instead of treating every tiny evidence step as a full accuracy point. It checks whether each policy reaches useful or scenario-supported assets, avoids hidden assets, chooses `no_reveal` for boundary cases, and distinguishes asset unlocks from configuration reveals.

| Scenario | Type | Reference id | Source basis | Expected behavior |
| --- | --- | --- | --- | --- |
| `main-ransomware-web-payload-loop` | main-fit | `cisa-lockbit-tool-transfer` | CISA LockBit advisory + ATT&CK T1190/T1608/T1105/T1204.002 | Exploit and payload-staging evidence should expose malware-analysis surfaces while keeping finance/admin assets hidden. |
| `main-source-map-transfer-choice-loop` | main-mixed | `cisa-ransomware-mixed` | CISA BianLian/LockBit advisories + ATT&CK discovery/tool-transfer behavior | Discovery and tool-transfer signals should expose developer and payload paths without opening database assets. |
| `main-finance-collection-loop` | main-collection | `cisa-red-team-aa23-059a` | CISA red-team file/data discovery, adapted to backup and finance archive clues | Backup and collection evidence should reveal the finance collection path. |
| `main-active-git-configuration-loop` | main-configuration | `cisa-red-team-aa23-059a` | CISA red-team config/credential discovery, adapted to active Git browsing | Active repository browsing should materialize Git-local configuration clues. |
| `main-boundary-enterprise-ad-no-reveal-loop` | main-boundary | `cisa-red-team-aa23-059a` | CISA red-team AD/SMB/credential techniques used as an out-of-scope boundary | Unsupported enterprise AD behavior should remain closed. |

### Replay Semantics

Each timeline step represents one controller decision point. The evaluator adds the step's `new_evidence` to the cumulative profile, runs the selected policy once, then updates simulated `unlocked_asset_ids` and `revealed_configurations` from the returned actions. Later steps therefore see assets and configuration variants opened earlier in the scenario.

This is an offline replay. It does not start Docker, open gateway routes, or generate live attacker traffic. It answers the decision-quality question: given this sequence of attacker evidence, did the policy make the key anchor decisions correctly without exposing hidden assets?

| Step field | Meaning |
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
| `source_refs` | Per-step source grounding. Each entry declares a reference id and exactness level. |

Only steps with `anchor_check: true` are used for exact reveal/no-reveal correctness. Non-anchor steps still accumulate evidence, update unlocked assets, and can fail the scenario if they open a hidden asset, but they do not fail exact-step accuracy just because the controller chose another reasonable asset. The main report `ok` condition is based on no hidden violations, no missing or unexpected anchor actions, no failed anchor no-reveal checks, and declared source traceability. `timeline_reveal_efficiency` is intentionally simple: revealed assets that the scenario later marks as touched divided by total revealed assets.

## `reveal_policy_scenarios.json`

Broad offline policy regression. This fixture keeps the smaller fit, boundary, scanner, mixed-signal, normal, configuration, and negative-control cases. It is useful for debugging exact controller/scenario alignment: scenarios can declare required `expected_reveals` and optional `allowed_reveals`; any extra action is reported as unexpected even when the asset-level reveal looks reasonable. Advisory/campaign sources provide behaviour grounding; local paths such as `.map`, `.bak`, `/admin`, or `/downloads/agent-update.bin` are honeynet-specific adaptations. Negative-control scenarios are marked as controlled negatives instead of being presented as real incident reproductions.

| Scenario | Type | Reference id | Source basis | Expected behavior |
| --- | --- | --- | --- | --- |
| `fit-web-exploit-download` | fit | `cisa-lockbit-tool-transfer` | CISA LockBit advisory + ATT&CK T1190/T1608/T1105 | Web exploit and download intent should reveal `malware-sink`. |
| `boundary-enterprise-ad-lateral` | boundary | `cisa-red-team-aa23-059a` | CISA Red Team advisory + ATT&CK T1003/T1021.002 | Enterprise AD-style evidence should not reveal unsupported catalogue assets. |
| `scanner-one-shot-web-probe` | scanner-like | `mitre-scan-exploit-negative` | ATT&CK T1595/T1190 as a controlled negative | One-shot scanner traffic should produce `no_reveal`. |
| `mixed-discovery-download-persistence` | mixed-signal | `cisa-ransomware-mixed` | CISA BianLian/LockBit advisories + ATT&CK T1083/T1608/T1548.003 | Discovery and payload signals should reveal `git-internal` plus `malware-sink`. |
| `false-positive-short-enumeration` | false-positive-reveal | `mitre-discovery-negative` | Controlled negative based on ATT&CK T1083 | Short plausible enumeration may reveal `git-internal`, but useful follow-up is empty. |
| `normal-source-map-git-discovery` | normal | `cisa-red-team-aa23-059a` | CISA red-team file/script/database findings adapted to source-map discovery | Source-map evidence should reveal `git-internal`. |
| `normal-backup-finance-share` | normal | `cisa-red-team-aa23-059a` | CISA red-team credential/data discovery in backups, scripts, and databases | Backup evidence should reveal `finance-share`. |
| `normal-admin-console-probe` | normal | `mitre-admin-web-discovery` | ATT&CK web/admin discovery and login probing patterns | Admin path probing should reveal `web-admin-console`. |
| `normal-password-ssh-canary` | normal | `cisa-red-team-aa23-059a` | CISA red-team SSH password discovery and remote-service attempt | Password and remote-access evidence should reveal `ssh-canary`. |
| `config-git-active-seeded-repo` | configuration | `cisa-red-team-aa23-059a` | CISA red-team file/script/database discovery, adapted to active repo browsing | While the attacker is on `git-internal`, swap to a seeded repository backend. |
| `config-finance-active-archive-index` | configuration | `cisa-red-team-aa23-059a` | CISA red-team data discovery, adapted to active share browsing | While the attacker is on `finance-share`, add a sensitive archive index. |
| `config-malware-active-dionaea-upgrade` | configuration | `cisa-lockbit-tool-transfer` | CISA LockBit tool-transfer behaviour adapted to same-path payload capture | While the attacker is on `malware-sink`, configure the higher-interaction `dionaea-capture` backend. |
| `config-stale-git-not-active-no-reveal` | configuration-negative | `active-path-negative-control` | Controlled negative for configuration reveal semantics | Do not change `git-internal` after the attacker has left that asset path. |

## `reveal_port_scenarios.json`

Engineering route validation. These scenarios verify that a selected asset maps to the correct fixed public port, and in live mode that the asset-gateway route table actually contains the expected route.

| Group | Examples | What It Checks |
| --- | --- | --- |
| Bootstrap | `bootstrap-internal-portal` | First internal discovery surface opens on `18080`. |
| Breadcrumb services | `git-env-breadcrumb`, `finance-backup-breadcrumb`, `ssh-password-breadcrumb` | Common evidence breadcrumbs select the expected fixed-port asset. |
| Admin and remote access | `web-admin-probe`, `vpn-admin-probe` | Admin and VPN surfaces map to their fixed ports. |
| Capture and upgrade backends | `dionaea-malware-upgrade`, `honeytrap-generic-probe` | Upgrade or capture targets expose the expected same-story backend ports. |
| Payload/exploit follow-up | `malware-exploit-probe`, `web-exploit-payload-probe`, `generic-transfer-honeytrap` | Exploit or transfer evidence opens the payload sink or generic capture route. |

## Source Traceability

Every offline reveal-policy scenario must state which behavior came from an official report or ATT&CK entry, what the local honeynet substitutes for that behavior, and whether the mapping is direct, technique-level, a local adaptation, or a negative control. The public sources ground behavior and ATT&CK technique families, not exact local strings. Paths such as `/assets/app.js.map`, `/.env.old`, `/backup/passwords_internal.txt`, and `/admin` are local cover-story artifacts used to emulate broader report-backed behaviors such as file discovery, credential discovery, admin surface probing, remote-service interest, and tool-transfer intent.

| Exactness level | Meaning |
| --- | --- |
| `direct` | The report describes the same behavior at roughly the same level of detail as the replay step. |
| `technique-level` | The source supports the ATT&CK technique or behavior family, but not this exact local path, file, or hostname. |
| `local-adaptation` | The local path, file, service, or asset is honeynet-specific and only simulates a source-backed behavior. |
| `negative-control` | The scenario is deliberately synthetic and tests no-reveal or false-positive behavior. |

| Reference id | Source | URL | How it is used |
| --- | --- | --- | --- |
| `cisa-lockbit-tool-transfer` | CISA AA23-075A LockBit 3.0 advisory | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a | Grounds public-facing exploitation, use of tools, command-and-control/tool-transfer behavior, and ransomware follow-up techniques. |
| `cisa-red-team-aa23-059a` | CISA AA23-059A Red Team key findings | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-059a | Grounds credential discovery, password-store findings, remote-service/lateral-movement interest, network service discovery, and AD boundary behavior. |
| `cisa-ransomware-mixed` | CISA AA23-136A BianLian plus LockBit advisory | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a | Grounds mixed discovery, tool download, share discovery, collection, and exfiltration-style behavior. |
| `mitre-admin-web-discovery` | MITRE ATT&CK Enterprise techniques | https://attack.mitre.org/techniques/enterprise/ | Grounds generic admin/login probing as ATT&CK technique-level behavior, not a named incident. |
| `mitre-scan-exploit-negative` | MITRE ATT&CK Enterprise techniques | https://attack.mitre.org/techniques/enterprise/ | Negative-control scan/exploit shape. |
| `mitre-discovery-negative` | MITRE ATT&CK Enterprise techniques | https://attack.mitre.org/techniques/enterprise/ | Negative-control discovery shape. |
| `active-path-negative-control` | Local evaluation control | local fixture only | Tests that configuration reveal does not happen after the attacker leaves the relevant active path. |
