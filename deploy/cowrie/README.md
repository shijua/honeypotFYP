# Cowrie Local Honeypot

This directory contains a minimal Cowrie SSH honeypot setup for collecting real SSH interaction logs and forwarding them into the MVP Cowrie adapter.

## Quick Start

Run the local Cowrie lab from the repository root:

```bash
./scripts/run_local_cowrie_lab.sh
```

For the adaptive behavior loop, use:

```bash
./scripts/run_adaptive_cowrie_demo.sh
```

Those scripts are kept in the main tree so simulation behavior and tests stay updated with the current runtime.

## Port Conflicts

If another process already owns `2222`, inspect it manually:

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
```

If Docker previously created `deploy/cowrie/var/lib/cowrie` as `nobody/nogroup`, reset the local lab directory once:

```bash
sudo mkdir -p deploy/cowrie/var/log/cowrie deploy/cowrie/var/lib/cowrie/tty
sudo chown -R "$(id -u):$(id -g)" deploy/cowrie/var
chmod -R u+rwX deploy/cowrie/var
```

## Manual mode

Use these steps if you want to keep the services running separately.

## 1. Prepare the log directory

The Cowrie container writes logs as its own user. For a local lab, make the bind mount writable before starting Docker:

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

Only change the compose port binding to `0.0.0.0:2222:2222` after the lab firewall and network isolation are ready.

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
