# Web Admin Interface

The 4tAnalyst web admin interface is a browser-based panel served at `/admin` on the same
port as the MCP server (default 8000). It runs in the same Python process with no additional
services or ports required.

## Accessing the interface

```
http://<server>:8000/admin
```

Log in with a local account created via the CLI (see [Admin Guide](admin-guide.md)).

## Tabs

### Dashboard

Real-time system health for the server running the MCP service:

- **Point-in-time cards** — current CPU %, memory %, disk % (auto-refresh every 30 seconds)
- **Time-series charts** — one Chart.js line graph per metric, with a range selector: 1h / 4h / 12h / 1d / 7d

### Graph

AI usage analytics across all engineers:

- **Time range** — 1h / 4h / 12h / 1d / 7d / 14d / custom date range
- **View: Tool Calls** — stacked bar chart by engineer
- **View: Tokens** — input vs. output token counts, per engineer or total
- **View: Cost ($)** — estimated cost line chart derived from the `pricing:` table in `credentials.yaml`
- **Summary table** — per-engineer totals for the selected range, sortable

Token data requires engineers to configure the optional Claude Code `Stop` hook
(see [workstation-onboarding.md](workstation-onboarding.md)). Without the hook, the Graph tab
shows tool call counts but no token or cost data.

### Admin (admin role only)

**ADOM & Token Management**

Displays all per-engineer MCP tokens from `credentials.yaml server.tokens`. Allowed ADOMs
are editable inline — changes take effect immediately without a server restart.

**User Management**

Manage local web UI accounts: add users, reset passwords, change roles, delete accounts.
Roles: `admin` (all tabs + config) / `viewer` (dashboard and graph, read-only).

## Authentication

The web UI uses local accounts stored in `data/users.json` (bcrypt-hashed passwords, gitignored).
MCP clients continue to use bearer tokens — the two auth systems are independent.

RADIUS/LDAP support is built into the architecture and can be enabled by populating
`web_admin.radius` in `credentials.yaml` without any code changes.
See [Admin Guide](admin-guide.md) for the upgrade path.

## Data storage

Usage and metrics data is stored in `data/analytics.db` (SQLite, WAL mode), separate from
the feedback/audit database (`data/feedback.db`). Default retention: 90 days, configurable
via `web_admin.analytics_retention_days` in `credentials.yaml`.
