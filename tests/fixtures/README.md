# Evaluation Fixtures

These fixtures are intentionally split by evaluation question.

## `reveal_policy_main_scenarios.json`

Main offline policy replay. This is the headline decision-quality fixture: it uses fewer, richer full-process timelines, exact checks only at `anchor_check` steps, and final scenario outcomes instead of treating every tiny evidence step as a full accuracy point. It checks whether each policy reaches useful/reasonable assets, avoids hidden assets, chooses `no_reveal` for boundary cases, and distinguishes asset unlocks from configuration reveals. The semantics are documented in `FULL_REPLAY_SCENARIO_DESIGN.md`, and detailed source mapping lives in `SCENARIO_SOURCE_TRACEABILITY.md`.

| Scenario | Type | Reference id | Source basis | Expected behavior |
| --- | --- | --- | --- | --- |
| `main-ransomware-web-payload-loop` | main-fit | `cisa-lockbit-tool-transfer` | CISA LockBit advisory + ATT&CK T1190/T1608/T1105/T1204.002 | Exploit and payload-staging evidence should expose malware-analysis surfaces while keeping finance/admin assets hidden. |
| `main-source-map-transfer-choice-loop` | main-mixed | `cisa-ransomware-mixed` | CISA BianLian/LockBit advisories + ATT&CK discovery/tool-transfer behavior | Discovery and tool-transfer signals should expose developer and payload paths without opening database assets. |
| `main-finance-collection-loop` | main-collection | `cisa-red-team-aa23-059a` | CISA red-team file/data discovery, adapted to backup and finance archive clues | Backup and collection evidence should reveal the finance collection path. |
| `main-active-git-configuration-loop` | main-configuration | `cisa-red-team-aa23-059a` | CISA red-team config/credential discovery, adapted to active Git browsing | Active repository browsing should materialize Git-local configuration clues. |
| `main-boundary-enterprise-ad-no-reveal-loop` | main-boundary | `cisa-red-team-aa23-059a` | CISA red-team AD/SMB/credential techniques used as an out-of-scope boundary | Unsupported enterprise AD behavior should remain closed. |

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
| `config-git-active-repo-db-clue` | configuration | `cisa-red-team-aa23-059a` | CISA red-team file/script/database credential discovery, adapted to active repo browsing | While the attacker is on `git-internal`, add a repository-local DB credential clue. |
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

## Official Source Links

| Source | URL |
| --- | --- |
| Reference id `cisa-lockbit-tool-transfer` | CISA LockBit plus ATT&CK T1190/T1608/T1105 local adaptation. |
| Reference id `cisa-red-team-aa23-059a` | CISA red-team file, credential, database, and remote-service behaviour local adaptation. |
| Reference id `mitre-scan-exploit-negative` | ATT&CK scanning/exploitation techniques used as a negative control. |
| Reference id `cisa-ransomware-mixed` | CISA BianLian and LockBit discovery/tool-transfer mixed-signal adaptation. |
| Reference id `mitre-discovery-negative` | ATT&CK discovery behaviour used as a false-positive control. |
| Reference id `mitre-admin-web-discovery` | ATT&CK admin/log/service discovery and login-probing adaptation. |
| Reference id `active-path-negative-control` | Local negative control for active-path configuration semantics. |
| CISA AA23-075A #StopRansomware: LockBit 3.0 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a |
| CISA AA23-059A Red Team Shares Key Findings | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-059a |
| CISA AA23-136A #StopRansomware: BianLian Ransomware Group | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a |
| CISA AA23-320A Scattered Spider | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a |
| CISA AA24-038A PRC State-Sponsored Actors Compromise U.S. Critical Infrastructure | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a |
| MITRE ATT&CK Enterprise Techniques | https://attack.mitre.org/techniques/enterprise/ |
