# Evaluation Fixtures

These fixtures are intentionally split by evaluation question.

## `reveal_policy_scenarios.json`

Offline policy replay. This is the main decision-quality evaluation: it checks whether each policy reveals reasonable assets, avoids hidden assets, and chooses `no_reveal` for scanner or boundary cases. Each scenario keeps `real_world_basis` and `transition_basis` in the JSON because those fields are part of the evaluation rationale. The official source links live in this README. The advisory/campaign source provides the behaviour chain; local paths such as `.map`, `.bak`, or `/admin` are honeynet-specific adaptations. Negative-control scenarios are marked as controlled negatives instead of being presented as real incident reproductions.

| Scenario | Type | Source basis | Expected behavior |
| --- | --- | --- | --- |
| `fit-web-exploit-download` | fit | CISA LockBit advisory + ATT&CK T1190/T1608/T1105 | Web exploit and download intent should reveal `malware-sink`. |
| `boundary-enterprise-ad-lateral` | boundary | CISA Red Team advisory + ATT&CK T1003/T1021.002 | Enterprise AD-style evidence should not reveal unsupported catalogue assets. |
| `scanner-one-shot-web-probe` | scanner-like | ATT&CK T1595/T1190 | One-shot scanner traffic should produce `no_reveal`. |
| `mixed-discovery-download-persistence` | mixed-signal | CISA BianLian/LockBit advisories + ATT&CK T1083/T1608/T1548.003 | Discovery and payload signals should reveal `git-internal` plus `malware-sink`. |
| `false-positive-short-enumeration` | false-positive-reveal | Controlled negative based on ATT&CK T1083 | Short plausible enumeration may reveal `git-internal`, but useful follow-up is empty. |
| `normal-source-map-git-discovery` | normal | CISA Scattered Spider advisory + ATT&CK T1083/T1213 | Source-map evidence should reveal `git-internal` and may continue to `admin-jumpbox`. |
| `normal-backup-finance-share` | normal | CISA Red Team/Scattered Spider advisories + ATT&CK T1213/T1005 | Backup evidence should reveal `finance-share`. |
| `normal-admin-console-probe` | normal | CISA Volt Typhoon advisory + ATT&CK T1654/T1046 | Admin path probing should reveal `web-admin-console`. |
| `normal-password-ssh-canary` | normal | CISA Red Team advisory + ATT&CK T1552.001/T1021.004 | Password and remote-access evidence should reveal `finance-share` plus `ssh-canary`. |

## `reveal_port_scenarios.json`

Engineering route validation. These scenarios verify that a selected asset maps to the correct fixed public port, and in live mode that the asset-gateway route table actually contains the expected route.

| Group | Examples | What It Checks |
| --- | --- | --- |
| Bootstrap | `bootstrap-internal-portal` | First internal discovery surface opens on `18080`. |
| Breadcrumb services | `git-env-breadcrumb`, `finance-backup-breadcrumb`, `ssh-password-breadcrumb` | Common evidence breadcrumbs select the expected fixed-port asset. |
| Admin and remote access | `web-admin-probe`, `vpn-admin-probe` | Admin and VPN surfaces map to their fixed ports. |
| High-interaction upgrades | `dionaea-malware-upgrade`, `honeytrap-generic-probe` | Upgrade targets expose the expected same-story backend ports. |
| Payload/exploit follow-up | `malware-exploit-probe`, `web-exploit-payload-probe`, `generic-transfer-honeytrap` | Exploit or transfer evidence opens the payload sink or generic capture route. |

## Official Source Links

| Source | URL |
| --- | --- |
| CISA AA23-075A #StopRansomware: LockBit 3.0 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a |
| CISA AA23-059A Red Team Shares Key Findings | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-059a |
| CISA AA23-136A #StopRansomware: BianLian Ransomware Group | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a |
| CISA AA23-320A Scattered Spider | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a |
| CISA AA24-038A PRC State-Sponsored Actors Compromise U.S. Critical Infrastructure | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a |
| MITRE ATT&CK Enterprise Techniques | https://attack.mitre.org/techniques/enterprise/ |
