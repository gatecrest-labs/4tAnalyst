# Security

## Credential handling

**`credentials.yaml` is gitignored and must never be committed.** It contains API keys for FortiManager and the 4THealth zone policy system. Use `credentials.yaml.example` as a template.

If you accidentally commit credentials:
1. Immediately revoke and rotate the affected API keys in the respective systems
2. Remove the file from git history using `git filter-repo` or contact your GitHub admin
3. Audit access logs on the affected systems for unauthorized use

All API credentials are stored on the central MCP server only. Engineer workstations hold no credentials — they connect to the central server over HTTPS/SSE.

## Network access

The central MCP server should have:
- **Outbound only** to FortiManager and 4THealth management IPs on port 443 (and NetBrain when integration is ready)
- **Inbound** from engineer workstation subnets on port 8000 only (unified server, bearer-token auth; front with TLS)
- **No internet access** required

Engineer workstations need only outbound HTTPS to the central server. No direct firewall management API access is required or recommended.

## What this system can and cannot do

**Read-only throughout.** All MCP tools make read-only API calls. No tool can create, modify, or delete firewall rules, objects, or policies. This is enforced at the API layer — the service accounts used have read-only profiles.

**No execution.** 4tAnalyst produces recommendations and peer review packages. The Ansible push that implements changes is a separate, human-initiated process outside this system.

**No credentials on workstations.** Engineers never need and should never have direct API access to FortiManager. If an engineer asks for API keys "to test locally," direct them to use the central MCP server instead.

## Accuracy limitations and advisory status

All tool outputs — zone policy verdicts, rule search results, naming validations, approval chains, and peer review packages — are **advisory only**. They are research aids, not authoritative decisions.

- **Policy verdicts reflect intended segmentation policy**, not the live state of firewall rules. ALLOWED means the zone policy permits the traffic in principle; it does not mean a rule exists or that the traffic will actually pass.
- **Zone resolution depends on the 4THealth database being current.** An IP recently moved to a new subnet, or a subnet not yet registered in 4THealth, will return UNKNOWN. Treat UNKNOWN as BLOCKED pending manual verification — do not treat it as "no policy found, probably okay."
- **Engineers are accountable for all decisions.** The tool accelerates research; it does not replace professional judgment or peer review.
- **Peer review packages are drafts**, not completed reviews. No AI-generated document should be filed as an official change record or audit evidence without human review and explicit attestation by the reviewing engineer.

## Engineer identity in the audit log (current limitation)

The audit log records an `engineer_id` string provided by the engineer at time of decision. This is **not authenticated** — any string can be entered. For audit purposes in a regulated environment (NERC CIP, HIPAA, PCI-DSS, or your organization's own change-management standard), do not rely solely on the audit log for identity verification until authenticated identity (AD/Entra) is implemented.

Until then, cross-reference recorded decisions against ServiceNow ticket history and CAB records for audit evidence. Do not begin recording official change decisions until this limitation is understood and accepted by the compliance team.

## Regulated-environment compliance posture

4tAnalyst is a research and documentation aid. It is **not a replacement for any step in your organization's documented change management process** — whether that process is governed by NERC CIP, HIPAA, PCI-DSS, SOX, or an internal policy. Before using 4tAnalyst outputs as part of an official change record:

1. Confirm with your compliance team that AI-assisted analysis tools are acceptable under your current documented procedures.
2. Ensure any filed documents are attested by a named human reviewer, not presented as AI-generated outputs.
3. Do not treat `review_requirements.yaml` approval chain values as authoritative until they have been validated and signed off by the compliance team.

## Data in this repository

This repository ships placeholder data only. Hostnames, ADOM names, device names and zone names in the
code, tests, docs and `*.example` files are fictional or generic (public vendor domains appear only as
FQDN examples). IPs are private (RFC 1918), documentation (RFC 5737) or well-known public addresses. Site-specific files stay local and are gitignored: `credentials.yaml`, `device_zone_map.yaml`,
`standards_mcp/naming.local.yaml`, `standards_mcp/policy_db.json` and `standards_mcp/policy-data/`. Build
your own from the `.example` templates and `python standards_mcp/build_policy_db.py`.

Before contributing, keep real environment details out of commits, including test fixtures and commit
metadata. `scripts/check-sensitive-strings.sh` (run in CI and by the `.githooks/pre-commit` hook) blocks a
list of known strings.

## Issuing engineer tokens

Engineers connect to the central MCP server using per-engineer bearer tokens scoped to one or more ADOMs. This section covers the admin workflow for creating and revoking those tokens.

### Generating a token

```bash
openssl rand -hex 32
```

This produces a 64-character hex string. Each engineer gets a unique token.

### Adding the token to credentials.yaml

Open `credentials.yaml` on the central server and add an entry under `server.tokens`:

```yaml
server:
  adom_restriction: true
  auth_token: "..."   # admin token — unchanged

  tokens:
    # Existing entries...
    - token: "a1b2c3d4..."        # 64-char hex from openssl rand -hex 32
      label: "firstname-lastname" # human-readable; appears in audit logs only
      adoms: ["OT-ADOM"]          # list the ADOMs this engineer needs
                                  # use ["*"] for full access (same as auth_token)
```

To restrict to multiple ADOMs: `adoms: ["OT-ADOM", "GAS-ADOM"]`.
To grant full access (e.g., a second admin or a tester): `adoms: ["*"]`.

After editing `credentials.yaml`, restart the unified server for the change to take effect:

```bash
systemctl restart 4tanalyst   # or however the server is managed at your site
```

### Sending the token to the engineer

Send the token over a secure channel — encrypted email, a privileged ticket in ServiceNow, or an internal secrets manager. Do not send it via unencrypted email, Teams/Slack DM (unless E2E encrypted), or document it in the firewall change ticket.

Tell the engineer:
- Their token value (64 hex chars)
- The central server hostname and port (e.g., `4tanalyst.internal.example.com:8000`)
- Which ADOMs they have access to, so they can verify
- To direct them to `docs/workstation-onboarding.md` if they need setup instructions

### Revoking a token

Remove the engineer's `tokens` entry from `credentials.yaml` and restart the server. The token is immediately invalid once the server reloads. No other action is required — the server carries no session state.

If you suspect a token was compromised (exposed in a chat log, committed to git, etc.):
1. Remove the entry from `credentials.yaml` immediately
2. Restart the server
3. Generate a new token and reissue to the engineer if their access should continue
4. Review the audit log (`feedback_mcp.get_audit_log`) for any unexpected activity under that engineer's label

### Disabling ADOM filtering entirely

If your deployment has a single team and all engineers need full access, set `adom_restriction: false` in `credentials.yaml`. Every recognized token (primary `auth_token` and all `tokens` entries) gets unrestricted access. Unrecognized tokens are still rejected with 401.

---

## Reporting vulnerabilities

If you discover a security issue in this codebase, please report it to your organization's security team directly rather than opening a public GitHub issue. Do not include exploit details or internal network information in public issues.
