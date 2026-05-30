# Scenario Source Traceability

This file records how each offline reveal-policy scenario is grounded. It is deliberately stricter than the compact `reference_id` field in the JSON fixture: every scenario must state which behavior came from an official report or ATT&CK entry, what the local honeynet substitutes for that behavior, and whether the mapping is direct, technique-level, a local adaptation, or a negative control.

## Source Index

| Reference id | Source | URL | How it is used |
| --- | --- | --- | --- |
| `cisa-lockbit-tool-transfer` | CISA AA23-075A LockBit 3.0 advisory | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a | Grounds public-facing exploitation, use of tools, command-and-control/tool-transfer behavior, and ransomware follow-up techniques. |
| `cisa-red-team-aa23-059a` | CISA AA23-059A Red Team key findings | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-059a | Grounds credential discovery, password-store findings, remote-service/lateral-movement interest, network service discovery, and AD boundary behavior. |
| `cisa-ransomware-mixed` | CISA AA23-136A BianLian plus LockBit advisory | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a | Grounds mixed discovery, tool download, share discovery, collection, and exfiltration-style behavior. |
| `mitre-admin-web-discovery` | MITRE ATT&CK Enterprise techniques | https://attack.mitre.org/techniques/enterprise/ | Grounds generic admin/login probing as ATT&CK technique-level behavior, not a named incident. |
| `mitre-scan-exploit-negative` | MITRE ATT&CK Enterprise techniques | https://attack.mitre.org/techniques/enterprise/ | Negative-control scan/exploit shape. |
| `mitre-discovery-negative` | MITRE ATT&CK Enterprise techniques | https://attack.mitre.org/techniques/enterprise/ | Negative-control discovery shape. |
| `active-path-negative-control` | Local evaluation control | local fixture only | Tests that configuration reveal does not happen after the attacker leaves the relevant active path. |

## Main Scenario Mapping

These are the richer scenarios used for headline policy results. They reuse the same official references as the broad regression fixture, but group multiple related steps into a full replay timeline. Local paths, hostnames, files, and asset names remain honeynet adaptations; the public sources ground the behavior and ATT&CK technique level, not the exact local strings.

### `main-ransomware-web-payload-loop`

| Step | Source behavior | Local evidence | Exactness | Anchor role |
| --- | --- | --- | --- | --- |
| `s1-public-exploit` | LockBit public-facing exploitation mapped to T1190. | `public_http_exploit_probe` with `php://filter`. | `local-adaptation` | First reveal anchor: `malware-sink`. |
| `s2-staging-interest` | Payload/resource staging behavior. | Continued exploit-shaped staging marker mapped to T1608. | `local-adaptation` | State accumulation. |
| `s3-transfer-intent` | Tool transfer / command-and-control behavior. | Local transfer marker mapped to T1105. | `technique-level` | Follow-up reveal anchor: `dionaea-capture`. |
| `s4-malware-sink-touch` | Attacker follows the revealed payload surface. | Access to `/staging/manifest.json` on `malware-sink`. | `local-adaptation` | Useful response evidence. |
| `s5-capture-followup` | Payload execution/capture follow-up. | T1204.002 on `dionaea-capture`. | `technique-level` | Final useful follow-up anchor. |

### `main-source-map-transfer-choice-loop`

| Step | Source behavior | Local evidence | Exactness | Anchor role |
| --- | --- | --- | --- | --- |
| `s1-source-map` | Discovery/file enumeration in ransomware reporting. | `/assets/app.js.map` source-map breadcrumb. | `local-adaptation` | State accumulation. |
| `s2-transfer` | Tool transfer behavior. | Exploit/payload marker mapped to T1105. | `technique-level` | Anchor: `git-internal` plus `malware-sink`. |
| `s3-revealed-payload-touch` | Follow-up collection on newly visible staging surface. | `/staging/archive-plan.txt` on `malware-sink`. | `local-adaptation` | Choice/touched-asset evidence. |
| `s4-privileged-tooling` | Privilege-escalation behavior. | Synthetic T1548.003 evidence. | `technique-level` | State accumulation. |
| `s5-final-useful-assets` | Local final-state check. | No new source event; checks that useful paths were reached. | `local-adaptation` | Final outcome anchor. |

### `main-finance-collection-loop`

| Step | Source behavior | Local evidence | Exactness | Anchor role |
| --- | --- | --- | --- | --- |
| `s1-backup-path` | File/data discovery from CISA red-team findings. | `/backup/db_backup_2024.sql.bak` as local backup clue. | `local-adaptation` | State accumulation. |
| `s2-data-from-local-system` | Data collection from local systems. | Backup clue mapped to T1005. | `technique-level` | Anchor: `finance-share`, with `ftp-archive` allowed. |
| `s3-finance-share-touch` | Access to stored data. | Finance archive CSV on the revealed share. | `local-adaptation` | Useful response evidence. |
| `s4-archive-transfer` | Archive transfer or staged collection. | FTP/archive evidence mapped to T1567.002. | `technique-level` | Diagnostic response evidence. |
| `s5-final-finance-check` | Local final-state check. | No new source event; checks finance path reached. | `local-adaptation` | Final outcome anchor. |

### `main-active-git-configuration-loop`

| Step | Source behavior | Local evidence | Exactness | Anchor role |
| --- | --- | --- | --- | --- |
| `s1-repo-config-access` | Repository/config browsing. | Active `git-internal` access to `/config/application-prod.yml`. | `local-adaptation` | Active-path configuration anchor: `git-deployment-ci-config`. |
| `s2-repo-file-discovery` | File/config discovery. | Active `git-internal` access to `/k8s/values-prod.yaml`. | `local-adaptation` | Active-path configuration anchor: `git-db-credential-clue`. |
| `s3-credential-clue-read` | Unsecured credentials in files. | Credential-like material on active Git path. | `local-adaptation` | Useful response evidence. |
| `s4-privileged-runbook-followup` | Privilege escalation follow-up. | Synthetic T1548.003 evidence. | `technique-level` | State accumulation. |
| `s5-final-config-check` | Local final-state check. | No new source event; checks Git configuration path reached. | `local-adaptation` | Final outcome anchor. |

### `main-boundary-enterprise-ad-no-reveal-loop`

| Step | Source behavior | Local evidence | Exactness | Anchor role |
| --- | --- | --- | --- | --- |
| `s1-credential-dumping` | Credential dumping. | Synthetic T1003 evidence. | `technique-level` | Boundary accumulation. |
| `s2-smb-lateral` | SMB/Admin Share lateral movement. | Synthetic T1021.002 evidence. | `technique-level` | Boundary accumulation. |
| `s3-ad-discovery` | Domain trust discovery. | Synthetic T1482 evidence. | `technique-level` | Boundary accumulation. |
| `s4-kerberos-abuse` | Kerberos credential abuse. | Synthetic T1558 evidence. | `technique-level` | Boundary accumulation. |
| `s5-boundary-final-no-reveal` | Account creation or enterprise persistence. | Synthetic T1136 evidence. | `technique-level` | No-reveal anchor. |

## Scenario Mapping

### `fit-web-exploit-download`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1190` | LockBit advisory maps exploitation of public-facing applications to T1190. | `public_http_exploit_probe` with `php://filter` is a local web-exploit probe. | `local-adaptation` | `malware-sink` may be revealed because exploit-shaped traffic is compatible with payload staging. |
| `s2-t1608` | LockBit tooling and infrastructure preparation are represented by resource-development/payload staging behavior. | The same exploit probe is treated as payload-staging intent. | `local-adaptation` | Keep the reveal focused on `malware-sink`; do not open data/admin assets. |
| `s3-t1105` | LockBit advisory describes command-and-control and tool movement behavior. | `ldap://` marker is a local payload-fetch indicator. | `local-adaptation` | `malware-sink` is the expected payload surface. |

### `boundary-enterprise-ad-lateral`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1003` | AA23-059A includes credential dumping and domain credential activity. | Synthetic T1003 profile evidence. | `technique-level` | No reveal: the small SaaS catalog does not model a domain controller. |
| `s2-t1021-002` | AA23-059A includes SMB/Admin Share lateral movement. | Synthetic T1021.002 profile evidence. | `technique-level` | No reveal: unsupported enterprise AD assets remain out of scope. |

### `scanner-one-shot-web-probe`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1190` | ATT&CK describes public-facing application exploitation as a technique. | One T1190 event without follow-up, path, credential, or active interaction. | `negative-control` | `no_reveal`; a single scanner-like hit should not open internal assets. |

### `mixed-discovery-download-persistence`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1083` | BianLian/LockBit reporting includes file discovery and environment reconnaissance. | `/assets/app.js.map` is a local source-map breadcrumb. | `local-adaptation` | Discovery/developer assets become plausible. |
| `s2-t1105` | Ransomware advisories include tool transfer and payload movement. | `php://filter` exploit marker is reused as local payload-transfer intent. | `local-adaptation` | Payload sink becomes plausible alongside the developer path. |
| `s3-t1548-003` | LockBit reporting includes privilege-escalation behavior. | Synthetic sudo-caching technique evidence. | `technique-level` | Expected outcome remains `git-internal` plus `malware-sink`; database assets stay hidden. |

### `choice-source-map-payload-followup`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1083` | Public reports support discovery, but not the exact source-map path. | `/assets/app.js.map` simulates source-code discovery. | `local-adaptation` | Developer path becomes plausible. |
| `s2-t1105` | LockBit-style tool-transfer behavior is represented at technique level. | `public_http_exploit_probe` with payload-shaped marker. | `local-adaptation` | Payload path becomes plausible. |
| `s3-t1213` | Collection from information repositories is represented through the source-map clue. | Source-map access is reused as local repository-collection evidence. | `local-adaptation` | The replay records that `malware-sink` is the touched direction. |

### `false-positive-short-enumeration`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1083` | ATT&CK supports file discovery as a technique. | A single source-map-style discovery event. | `negative-control` | A small reveal may be explainable, but useful follow-up is intentionally empty. |

### `normal-source-map-git-discovery`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1083` | AA23-059A describes discovery and enumeration behavior. | `/assets/app.js.map` is a local breadcrumb for code/config discovery. | `local-adaptation` | `git-internal` becomes a reasonable developer asset. |
| `s2-t1213` | Collection from information repositories is an ATT&CK behavior. | Source-map access is interpreted as local source-repository interest. | `local-adaptation` | `git-internal` is the expected reveal. |

### `normal-backup-finance-share`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1213` | AA23-059A and ATT&CK support collection/discovery of files and repositories. | `/backup/db_backup_2024.sql.bak` is a local backup-file clue. | `local-adaptation` | `finance-share` becomes reasonable. |
| `s2-t1005` | Data from local systems is a general collection behavior. | The backup path is reused as local data-collection evidence. | `local-adaptation` | `finance-share` remains the expected reveal. |

### `normal-admin-console-probe`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1110` | ATT&CK supports brute-force/login probing behavior. | `/admin` is a local admin-login surface. | `local-adaptation` | `web-admin-console` is reasonable, but this is not a named incident replay. |
| `s2-t1078` | Valid-account abuse is a common ATT&CK behavior. | `/admin` is reused as local credential-use interest. | `local-adaptation` | `web-admin-console` remains the expected reveal. |

### `normal-password-ssh-canary`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1552-001` | AA23-059A includes unsecured credential and password-store findings. | `/backup/passwords_internal.txt` is a local credential breadcrumb. | `local-adaptation` | Remote-access assets become plausible. |
| `s2-t1021-004` | AA23-059A includes remote-service/lateral-movement behavior. | The password breadcrumb is mapped to SSH remote-service interest. | `local-adaptation` | `ssh-canary` is the expected reveal. |

### `config-git-active-repo-db-clue`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1213` | AA23-059A supports collection of internal files and repositories. | Active `git-internal` access to `/config/application-prod.yml`. | `local-adaptation` | Configuration reveal is allowed only because the attacker is on the Git path. |
| `s2-t1083` | File/config discovery is a supported technique. | Active `git-internal` access to `/k8s/values-prod.yaml`. | `local-adaptation` | The active path remains Git. |
| `s3-t1552-001` | Unsecured credentials are report-backed at technique level. | Local repo config contains credential-like material. | `local-adaptation` | Add `git-db-credential-clue` or equivalent Git-local config. |

### `config-finance-active-archive-index`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1005` | Collection of local data is represented at ATT&CK technique level. | Active `finance-share` archive path access. | `local-adaptation` | Add `finance-backup-archive-index` on the same active surface. |

### `config-malware-active-dionaea-upgrade`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1105` | LockBit-style tool transfer and payload movement. | Active `malware-sink` download of `/downloads/agent-update.bin`. | `local-adaptation` | Same-path upgrade to `dionaea-capture` becomes reasonable. |
| `s2-t1204-002` | User execution of malicious files is represented at technique level. | The same local binary path is treated as execution-follow-up evidence. | `local-adaptation` | Configure `malware-dionaea-same-port-upgrade`. |

### `config-stale-git-not-active-no-reveal`

| Step | Source behavior | Local evidence | Exactness | Expected reveal |
| --- | --- | --- | --- | --- |
| `s1-t1213` | The technique is collection, but the active path is no longer Git. | Recent activity is on `finance-share`, while the candidate configuration would modify `git-internal`. | `negative-control` | `no_reveal`; configuration reveal must not assume the attacker will revisit an old asset. |
