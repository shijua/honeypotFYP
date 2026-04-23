# Cowrie Local Honeypot

This directory contains a minimal Cowrie SSH honeypot setup for collecting real
SSH interaction logs and forwarding them into the MVP Cowrie adapter.

## Quick start

Run one command from the repository root:

```bash
./scripts/run_local_cowrie_lab.sh
```

This starts the Cowrie adapter API, starts the Cowrie Docker container, starts
the JSON log forwarder, and opens `ssh -p 2222 root@127.0.0.1`. When you leave
the SSH session, the script shuts the services down.

Each run rotates the previous `deploy/cowrie/var/log/cowrie/cowrie.json` to a
timestamped `.bak` file before starting Cowrie, so the forwarder captures the
current session from the beginning without replaying old lab data.

Each run also removes the previous MVP runtime JSON state for this local Cowrie
demo. The file-backed repositories recreate missing files with empty default
JSON shapes when the adapter starts:

- `data/runtime/bindings.json`
- `data/runtime/cowrie_observations.json`
- `data/runtime/evidence.json`
- `data/runtime/profiles.json`

## Adaptive port-opening demo

To test the full local behavior loop where Cowrie commands update the profile
and trigger the controller/orchestrator to open new internal asset ports, run:

```bash
./scripts/run_adaptive_cowrie_demo.sh
```

Inside the Cowrie shell, try `id`, `whoami`, `uname -a`, or `ls -la /tmp`.
Watch the adaptive controller output with:

```bash
tail -f deploy/cowrie/var/adaptive-controller-loop.log
```

The adaptive loop is deliberately rate-limited for explainability: one new
profile evidence batch can trigger at most one asset unlock. The progress file
`data/runtime/adaptive_loop_state.json` prevents the same evidence from opening
more ports on later ticks.

Generate a compact report for the run with:

```bash
.venv/bin/python scripts/summarize_adaptive_demo.py \
  --write-report data/runtime/adaptive_demo_report.json
```

The report explains observed Cowrie events, recent profile tactics, controller
decisions, unlocked assets, ATT&CK techniques such as `T1110`, any real Docker
port mappings, and whether Docker still reports the container as present.

If a run is interrupted, clean up containers, service processes, and runtime
JSON state with:

```bash
./scripts/run_adaptive_cowrie_demo.sh cleanup
```

At startup the script stops:

- its previous `dynamic-honeynet-cowrie` compose container
- a legacy Docker container named `cowrie`, if one is running

If another process still owns `2222`, inspect it manually:

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
```

If Docker previously created `deploy/cowrie/var/lib/cowrie` as
`nobody/nogroup`, reset the local lab directory once:

```bash
sudo mkdir -p deploy/cowrie/var/log/cowrie deploy/cowrie/var/lib/cowrie/tty
sudo chown -R "$(id -u):$(id -g)" deploy/cowrie/var
chmod -R u+rwX deploy/cowrie/var
```

## Manual mode

Use these steps if you want to keep the services running separately.

## 1. Prepare the log directory

The Cowrie container writes logs as its own user. For a local lab, make the bind
mount writable before starting Docker:

```bash
mkdir -p deploy/cowrie/var/log/cowrie
mkdir -p deploy/cowrie/var/lib/cowrie/tty
chmod 0777 \
  deploy/cowrie/var \
  deploy/cowrie/var/log \
  deploy/cowrie/var/log/cowrie \
  deploy/cowrie/var/lib \
  deploy/cowrie/var/lib/cowrie \
  deploy/cowrie/var/lib/cowrie/tty
```

## 2. Start the Cowrie adapter API

```bash
/home/wh1322/honeypot/.venv/bin/python -m uvicorn services.cowrie.app:app --host 127.0.0.1 --port 8081
```

## 3. Start Cowrie

```bash
docker-compose -f deploy/cowrie/docker-compose.yml up
```

By default the SSH honeypot is only reachable on localhost:

```text
127.0.0.1:2222 -> Cowrie SSH
```

Only change the compose port binding to `0.0.0.0:2222:2222` after the lab
firewall and network isolation are ready.

## 4. Forward Cowrie JSON logs into the adapter

Open a second terminal:

```bash
/home/wh1322/honeypot/.venv/bin/python scripts/forward_cowrie_json.py \
  --log-file deploy/cowrie/var/log/cowrie/cowrie.json \
  --adapter-url http://127.0.0.1:8081/v1/cowrie/events
```

## 5. Generate a local test event

Open a third terminal:

```bash
ssh -p 2222 root@127.0.0.1
```

Use fake passwords only. Then check:

```bash
cat data/runtime/cowrie_observations.json
cat data/runtime/evidence.json
cat data/runtime/profiles.json
```
