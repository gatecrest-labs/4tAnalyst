# Admin Guide — 4tAnalyst Web Interface

## Initial Setup

**1. Generate a secret key**

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Add the output to `credentials.yaml` under `web_admin.secret_key`.

**2. Create the first admin user**

```bash
python -m fwanalyst_server.admin create-user <username> --role admin
```

Password is prompted interactively and never logged.

**3. Start the server in HTTP mode**

```bash
MCP_TRANSPORT=http FW_ANALYST_TOKEN=<token> uv run python -m fwanalyst_server
```

The admin UI is at `http://<server>:8000/admin`.

## User Management (CLI)

```bash
python -m fwanalyst_server.admin create-user alice --role viewer
python -m fwanalyst_server.admin list-users
python -m fwanalyst_server.admin reset-password alice
python -m fwanalyst_server.admin delete-user alice
```

Roles: **admin** (all tabs + config changes) / **viewer** (dashboard and graph, read-only).

## User Management (Web UI)

Log in as an admin, click the **Admin** tab. The User Management section lists all accounts with options to reset passwords, toggle roles, and delete users. An admin cannot delete their own account.

## ADOM Management

The **Admin** tab also shows all per-engineer MCP tokens from `credentials.yaml server.tokens`. Edit the **Allowed ADOMs** column inline and click **Save** to update both the in-memory config (takes effect immediately, no restart needed) and `credentials.yaml` on disk.

## Analytics Retention

Default: 90 days. To change, edit `credentials.yaml`:

```yaml
web_admin:
  analytics_retention_days: 60
```

Restart the server for the new retention period to take effect.

## Token Cost Configuration

Edit the `pricing:` section of `credentials.yaml` to match current Bedrock rates:

```yaml
pricing:
  claude-sonnet-5:
    input_per_million: 3.00
    output_per_million: 15.00
```

## RADIUS/LDAP Upgrade

When ready, uncomment and populate the `web_admin.radius:` block in `credentials.yaml`. The `authenticate()` function in `admin_auth.py` checks RADIUS first, with local bcrypt as break-glass fallback — no other code changes needed.

## Tabs Overview

### Dashboard

System health snapshot: CPU, memory, disk usage. Includes point-in-time metrics and historical trends over the selected time range. Color-coded indicators warn when resources exceed configured thresholds.

### Graph

Token usage and cost analytics. Select a time range (1 day, 7 days, 30 days) and view token consumption by user, model, and direction (input vs. output). Estimated cost is calculated using the `pricing:` section in `credentials.yaml`.

### Admin

**User Management**: List, create, reset password, delete, and toggle roles (admin ↔ viewer). Inline password resets are supported without needing CLI access.

**ADOM Restrictions**: Edit per-token ADOM restrictions inline from the table. Changes take effect immediately without a server restart.
