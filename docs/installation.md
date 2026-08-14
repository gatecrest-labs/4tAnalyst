# Installation

## Overview

4tAnalyst has two installation targets:
1. **Central MCP server** — a Linux VM on your internal network that runs the MCP servers and holds all firewall API credentials
2. **Engineer workstations** — each engineer's laptop needs only Claude Code pointed at the central server

---

## Central MCP server

### Hardware requirements

| Use case | vCPU | RAM | Disk |
|---|---|---|---|
| Development / pilot (1–2 engineers) | 4 | 8 GB | 50 GB |
| Team (5–10 engineers) | 8 | 16 GB | 100 GB |

### Network requirements

The server needs outbound access to:
- FortiManager management IP(s) on port 443
- 4THealth server IP on port 443
- NetBrain server IP on port 443 (when the integration is available)

Engineer laptops need inbound access to the MCP server on port 443 only (via the nginx TLS reverse proxy — see [TLS Setup](tls-setup.md)). Port 8000 should be restricted to localhost once nginx is in place.

No internet access is required.

### 1. Install system dependencies

```bash
# RHEL 8/9 (production target)
sudo dnf install -y python3.11 git curl

# Ubuntu 22.04
sudo apt update && sudo apt install -y python3.11 git curl

# Install uv (Python package manager) system-wide so all users (including 4tanalyst) can use it
curl -LsSf https://astral.sh/uv/install.sh | sudo UV_INSTALL_DIR=/usr/local/bin sh
```

### 2. Create the service account

Create a dedicated `4tanalyst` system account. Its home directory (`/opt/4tanalyst`) becomes the repo root — `useradd` creates it automatically.

```bash
sudo useradd --system --shell /sbin/nologin --create-home --home-dir /opt/4tanalyst 4tanalyst
```

### 3. Clone the repository

Because `useradd` pre-creates `/opt/4tanalyst`, `git clone` will refuse to use it. Initialize in-place instead:

```bash
sudo -u 4tanalyst bash -c "
  cd /opt/4tanalyst &&
  git init &&
  git remote add origin <repo-url> &&
  git fetch &&
  git checkout main
"
```

> All subsequent setup commands must run as the `4tanalyst` user (`sudo -u 4tanalyst`) or from within `sudo -u 4tanalyst bash`. Never run them as root or your own account — doing so will create files owned by the wrong user.

### 4. Create a virtual environment and install packages

`uv` must be told to use the `4tanalyst` home directory and to ignore any config files from the installing user's account:

```bash
sudo -u 4tanalyst bash -c "HOME=/opt/4tanalyst UV_NO_CONFIG=1 /usr/local/bin/uv venv --python 3.11 /opt/4tanalyst/.venv && \
    cd /opt/4tanalyst && HOME=/opt/4tanalyst UV_NO_CONFIG=1 /usr/local/bin/uv pip install \
    -e mcp_common/ -e standards_mcp/ -e fortimanager_mcp/ -e feedback_mcp/ \
    -e intake_mcp/ -e zone_mcp/ -e fwanalyst_server/"
```

Verify all 7 editable packages installed into the venv:

```bash
sudo -u 4tanalyst bash -c "HOME=/opt/4tanalyst UV_NO_CONFIG=1 /usr/local/bin/uv pip list --python /opt/4tanalyst/.venv/bin/python" | \
    grep -E "standards|fortimanager|feedback|intake|zone|fortigate-change-planner|fwanalyst|mcp"
```

You should see all 7 editable packages listed with their paths under `/opt/4tanalyst`, plus `fortigate-change-planner` (pulled in transitively as a git dependency of `fwanalyst_server`, not editable, no local path under `/opt/4tanalyst`).

### 6. Create the first admin user

Before starting the server in HTTP mode, create at least one web admin account:

```bash
sudo -u 4tanalyst python -m fwanalyst_server.admin create-user <username> --role admin
# Password is prompted interactively and never logged
```

### 7. Add web_admin config to credentials.yaml

Generate a secret key and add it to `credentials.yaml`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

```yaml
web_admin:
  secret_key: "<output from above>"
  session_lifetime_hours: 8
  analytics_retention_days: 90

pricing:
  claude-sonnet-5:
    input_per_million: 3.00
    output_per_million: 15.00
  default:
    input_per_million: 3.00
    output_per_million: 15.00
```

The admin UI is then available at `http://<server>:8000/admin` once the server starts.

### 8. Configure credentials

```bash
sudo -u 4tanalyst bash -c "cd /opt/4tanalyst && cp credentials.yaml.example credentials.yaml"
# Edit credentials.yaml — see Configuration for field descriptions
sudo -u 4tanalyst nano /opt/4tanalyst/credentials.yaml
```

### 9. Start the servers

For initial testing, start the server manually. Host/port are set via
`FASTMCP_HOST`/`FASTMCP_PORT` env vars, not CLI flags — the installed
`mcp` version's `FastMCP.run()` only accepts `transport`:

```bash
sudo -u 4tanalyst bash -c "
  cd /opt/4tanalyst &&
  MCP_TRANSPORT=http FASTMCP_HOST=0.0.0.0 FASTMCP_PORT=8000 \
    FW_ANALYST_TOKEN=<token> /opt/4tanalyst/.venv/bin/python -m fwanalyst_server
"
```

For production, use Docker Compose — see `docker-compose.yml` in the repository root.

### 8. Enable automatic startup on boot (RHEL/Linux)

A systemd unit file is included at `systemd/4tanalyst.service`. It runs the server as the `4tanalyst` user and restarts it automatically on failure.

**Create the environment file** (holds the auth token — never committed to the repo):

```bash
sudo mkdir -p /etc/4tanalyst
sudo bash -c "echo 'FW_ANALYST_TOKEN=<your-token-here>' > /etc/4tanalyst/env"
sudo chmod 600 /etc/4tanalyst/env
sudo chown 4tanalyst:4tanalyst /etc/4tanalyst/env
```

**Create the directories the unit is allowed to write to** (the unit runs with `ProtectSystem=strict`, so anywhere it writes at runtime must be listed in `ReadWritePaths=` and must exist and be owned by the service user before it starts):

```bash
sudo mkdir -p /opt/4tanalyst/output /var/lib/4tanalyst
sudo chown 4tanalyst:4tanalyst /opt/4tanalyst/output /var/lib/4tanalyst
```

**Install and enable the service:**

```bash
sudo cp /opt/4tanalyst/systemd/4tanalyst.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable 4tanalyst
sudo systemctl start 4tanalyst
```

**Verify it is running:**

```bash
sudo systemctl status 4tanalyst
```

The service will now start automatically on every reboot. To view logs:

```bash
sudo journalctl -u 4tanalyst -f
```

### 9. Smoke test

From the server, verify auth is enforced using either the pure-Python tester or the shell script:

```bash
sudo -u 4tanalyst bash -c "cd /opt/4tanalyst && uv run python scripts/run_smoke.py"
# or
sudo -u 4tanalyst bash -c "cd /opt/4tanalyst && ./scripts/smoke-test.sh"
```

Both check port 8000: an unauthenticated request must return `401`, a request with the token must not.

---

## Docker Compose

`docker-compose.yml` in the repo root runs the unified fwanalyst server for local dev (mounts the repo so edits are picked up live). `docker-compose.ci.yml` is the CI variant — built image, no mounts. `docker-compose.example.yml` is a conservative starting point if you're adapting this for a different deployment target.

```bash
sudo -u 4tanalyst bash -c "cd /opt/4tanalyst && docker compose up"
```

Developer helper scripts (local dev) — run all as the `4tanalyst` user:

- scripts/start-all.sh — start the unified server in the background (activates .venv if present)
  - Usage: `sudo -u 4tanalyst bash -c "cd /opt/4tanalyst && ./scripts/start-all.sh"`
- scripts/smoke-test.sh — quick curl-based auth check against port 8000
  - Usage: `sudo -u 4tanalyst bash -c "cd /opt/4tanalyst && ./scripts/smoke-test.sh"`
- scripts/run_smoke.py — pure-Python smoke tester (no extra packages)
  - Usage: `sudo -u 4tanalyst bash -c "cd /opt/4tanalyst && uv run python scripts/run_smoke.py"`

Systemd template (VM deployment, e.g. RHEL)

- A systemd unit template for the unified server is provided at `systemd/4tanalyst.service` (one unit — `MCP_TRANSPORT=http` plus `FW_ANALYST_TOKEN` via EnvironmentFile). The unit runs as the `4tanalyst` user — ensure `User=4tanalyst` is set in the `[Service]` section. Adjust ExecStart and paths for your host environment.

If you prefer to maintain your own start script, the commands below show what scripts/start-all.sh runs:

```bash
sudo -u 4tanalyst bash -c "
  cd /opt/4tanalyst &&
  MCP_TRANSPORT=http FASTMCP_HOST=0.0.0.0 FASTMCP_PORT=8000 \
    FW_ANALYST_TOKEN=<token> uv run python -m fwanalyst_server &
  wait
"
```

---

## Engineer workstations

Engineers need only Claude Code — no Python, no API credentials, no local server.

### 1. Install Claude Code

Download from [claude.ai/code](https://claude.ai/code). Available for macOS, Windows (native and WSL2), and Linux.

### 2. Get a slim checkout (skills and config only)

```bash
git clone --filter=blob:none --sparse <repo-url> 4tAnalyst-workstation
cd 4tAnalyst-workstation
git sparse-checkout set .claude scripts .mcp.json.example
```

### 3. Configure MCP server connections

Copy the example, fill in the central server hostname, and set your bearer token as an environment variable (not in the file):

```bash
cp .mcp.json.example .mcp.json
# Edit .mcp.json — replace <central-server>
export FW_ANALYST_CLIENT_TOKEN="<your-token-here>"   # shell profile or OS keychain
```

See [Configuration — Engineer workstations](configuration.md#engineer-workstations) for the full config reference, and `docs/workstation-onboarding.md` for the step-by-step setup.

### 4. Verify the connection

Open the `4tAnalyst` directory in Claude Code and type:

```
/check-policy 10.1.0.1 10.2.0.1
```

If the zone policy server is reachable you'll get a verdict back. If you get an error, see [Troubleshooting](troubleshooting.md).
