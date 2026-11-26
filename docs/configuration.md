# Configuration

## credentials.yaml (central server only)

`credentials.yaml` lives at the repo root on the central server. It is gitignored and must never be committed. Copy `credentials.yaml.example` to `credentials.yaml` and fill in real values.

### FortiManager

```yaml
fortimanager:
  hosts:
    - host: "10.x.x.x"       # FortiManager primary management IP
      api_key: "your-key"
    - host: "10.x.x.x"       # FortiManager secondary (optional)
      api_key: "your-key"
  port: 443
  verify_ssl: false
  version: "7.4"              # set to "7.6" after migration
```

`api_key` must come from a **REST API Administrator** account, not a regular
admin's password. FortiManager has two distinct admin types with different
auth flows on the JSON-RPC API:

- A regular admin (username + password) logs in via `/sys/login/user` and
  gets back a session token.
- A **REST API Administrator** has no password at all — the "API Key" shown
  on its config page (with a "Regenerate" button, not a "Change Password"
  field) is sent as an `Authorization: Bearer <key>` HTTP header on every
  call, with `session: null`. There is no login step and no session to
  expire — `fortimanager_mcp` uses this mode exclusively.

**Creating a REST API Administrator account:**
1. Log in to FortiManager as a super-user
2. Go to System Settings → Admin → Administrators → Create New → **REST API Administrator**
3. Set **Admin Profile** to a read-only profile (or `Super_User` for lab/test use)
4. Set **JSON API Access** to `Read-Write` (or `Read` if only read-only tools are needed) — without this, every call fails with a generic `-22 "Login fail"` even though no login is actually attempted
5. Set **Trusted Hosts** to include the IP range the MCP server calls from — a mismatch here also produces the same generic `-22` error, indistinguishable from a bad key without checking both settings
6. Copy the **API Key** shown on this page into `credentials.yaml`'s `api_key` field

### Zone policy (4THealth)

```yaml
zone_policy:
  base_url: "https://<4thealth-host-or-ip>"
  token: "4th_your-token-here"
  verify_ssl: "/path/to/internal-ca.pem"   # prefer a CA bundle path over `false`
  timeout: 30                              # per-request timeout in seconds
```

`verify_ssl` accepts a bool (`false` to skip verification — self-signed cert, not recommended past pilot; `true` to verify against the system trust store) or a string path to a CA bundle PEM file, passed straight through to `requests`' `verify` parameter. Prefer the CA bundle path over `false` once your internal CA can issue a cert for the 4THealth host.

The Bearer token is issued by the 4THealth application admin. Store it in the `token` field — the `Bearer ` prefix is added automatically.

---

## Environment variables

All credential paths can be overridden with environment variables. This is useful for containerised deployments where secrets are injected at runtime.

| Variable | Default | Purpose |
|---|---|---|
| `CREDENTIALS_FILE` | `<repo-root>/credentials.yaml` | Path to credentials file |
| `STANDARDS_POLICY_DB` | `standards_mcp/policy_db.json` | Path to zone policy DB (if using local file fallback) |
| `STANDARDS_NAMING_YAML` | `standards_mcp/naming.yaml` | Path to naming conventions file |
| `STANDARDS_REVIEW_YAML` | `standards_mcp/review_requirements.yaml` | Path to review requirements file |
| `FW_ANALYST_RATE_LIMIT_MAX` | `300` | Max HTTP requests per MCP session per window before a `429`; set to `0` to disable |
| `FW_ANALYST_RATE_LIMIT_WINDOW_SECONDS` | `60` | Sliding window length (seconds) for the rate limit above |
| `FW_ANALYST_ALLOWED_HOSTS` | *(unset)* | Comma-separated Host-header values engineers connect with (e.g. `central-server.internal.example.com:8000`), for DNS-rebinding protection. Falls back to `credentials.yaml` `server.allowed_hosts`. Unset keeps the MCP SDK default (localhost/127.0.0.1/`[::1]` only), which rejects real engineer traffic — set this before exposing the server on its deployed hostname |

---

## Policy export sanitizer (workstation)

Used by `/sanitize-policy` and `/review-policy`; nothing on the central server.

| Item | Default | Purpose |
|---|---|---|
| Terms file | `~/.config/4tanalyst/sanitize-terms.txt` (override with `--terms PATH`; `--no-terms` skips it with a warning) | Company/site names to scrub. One literal, case-insensitive term per line; optional `term=PLACEHOLDER`; `#` starts a comment. Terms of 4+ characters also match inside longer words; shorter terms only as whole tokens. Unnamed terms become `ORG`, then `SITE-1`, `SITE-2`, … |
| Map directory | `~/.local/share/4tanalyst/sanitize/` | Local real-to-fake maps (`<run-id>.map.json`, mode 0600, directory 0700 when the tool creates it). Refused inside the repo or a synced folder (OneDrive, CloudStorage, iCloud/Mobile Documents, Dropbox, Google Drive). Maps expire after 30 days. |
| `FW_ANALYST_SANITIZE_DIR` | *(unset)* | Environment variable overriding the map directory. A pre-existing directory keeps its own permissions. |
| Export / output folders | `~/policy-exports/` (raw, renamed `export-*.json`), `~/policy-sanitized/` (sanitized), `output/policy-review/` (findings JSON + HTML report), `~/policy-mapped/` (map-back output, real values) | Conventions used by the skills. |

Example terms file (invented values):

```
# company and site terms to scrub
acme
acme-hq=SITE_A
```

---

## Engineer workstations

Engineers connect to the central server via Claude Code's MCP configuration. No credentials are stored on workstations.

### Project-level config (required)

Create `.mcp.json` in the workstation checkout root (copy from the example shipped in the repo):

```bash
cp .mcp.json.example .mcp.json
```

Then fill in the real hostname:

```json
{
  "mcpServers": {
    "4tanalyst": {
      "type": "http",
      "url": "https://<central-server>/mcp",
      "headers": {
        "Authorization": "Bearer ${FW_ANALYST_CLIENT_TOKEN}"
      }
    }
  }
}
```

Claude Code expands `${FW_ANALYST_CLIENT_TOKEN}` from your environment at connect time — set it in your shell profile or OS keychain, do not paste the token into the file. `.mcp.json` is gitignored regardless, as defense in depth. Use `https://` on port 443 (nginx terminates TLS and proxies to the internal uvicorn process on port 8000 — do not connect to port 8000 directly from workstations).

See `docs/workstation-onboarding.md` for the full step-by-step setup including how to request a bearer token.

### Verifying the connection

In Claude Code, run:

```
/check-policy 10.1.0.1 10.2.0.1
```

You should get a zone verdict within a few seconds. If you get a timeout or "server not found" error, see [Troubleshooting](troubleshooting.md).

---

## Standards files (team-maintained)

These two files live in `standards_mcp/` and are checked into the repo. The team owns them — changes drive MCP tool output directly.

### naming.yaml

Defines object naming conventions per platform. The placeholder values shipped in the repo must be replaced with your actual standards before the `/validate-rule` skill produces accurate results.

Key sections to fill in:
- `platforms.fortigate.conventions` — naming patterns for host, network, service, and rule objects on FortiGate
- `log_settings` — required logging configuration per rule category

### review_requirements.yaml

Defines the approval chain per risk level. Replace the placeholder role names with actual roles from your org chart, and confirm the change window definitions match your CAB process.

After editing either file, restart the `standards_mcp` server (or the process picks up the changes on next startup — they are cached per process lifetime).
