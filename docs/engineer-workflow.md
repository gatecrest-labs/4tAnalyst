# Engineer Workflow Guide

This guide covers everything a firewall engineer needs to use 4tAnalyst once the system is fully deployed: workstation setup, how to work a request through the system, how data flows between components, and how to troubleshoot the most common failures.

---

## Admin dashboard

The 4tAnalyst server includes a web admin interface at `http://<server>:8000/admin`.
Engineers with viewer access can check the system health dashboard and view usage analytics.
Admins additionally manage ADOM access restrictions and user accounts.

See [Web Admin Interface](web-admin.md) for full details.

---

## 1. Workstation setup

You need three things on your laptop: Claude Code, a slim sparse-checkout of this repo, and a pointer to the central MCP server. You never install Python, credentials, or any MCP packages locally, and you never handle FortiManager/4THealth API keys — those live only on the central RHEL server (see `SECURITY.md`).

### Why a checkout is needed at all

Two pieces of the workflow run locally on your laptop, not on the central server:
- **Slash commands** (`/analyze-request`, `/check-policy`, etc.) — these are Claude Code project skills defined under `.claude/skills/`, which Claude Code only discovers when you run it from inside a directory containing that folder.
- **Report rendering** — the final step of `/analyze-request` runs `scripts/render_report.py` locally to produce `report.html`/`implementation.conf` for ticket attachment. It's a stdlib-only script; no credentials or network calls involved.

Everything else — zone verdicts, FortiManager rule search, naming/logging checks — happens on the central server over MCP; your laptop never touches that data directly.

### Get a slim checkout of the repo (one-time)

Rather than a full clone, use a sparse checkout so you only pull down `.claude/` and `scripts/` — not the server packages, tests, or docs you don't need:

```bash
git clone --filter=blob:none --sparse <repo-url> 4tanalyst-workstation
cd 4tanalyst-workstation
git sparse-checkout set .claude scripts .mcp.json.example
```

Your team access to this repo should be **read-only** — engineers use the checkout, they don't push changes to skills or server code. If you spot a bug in a skill or the naming conventions it enforces, report it to the FW engineering team (see `CONTRIBUTING.md`) rather than editing your local copy.

To pick up updates later (new/changed skills, fixes to the render script), just run:

```bash
git pull
```

from inside `4tanalyst-workstation`.

### Install Claude Code

Claude Code runs in your terminal. Install it from [claude.ai/code](https://claude.ai/code). You will need an Anthropic subscription (Claude Max or API access) — confirm with IT that your account is provisioned before starting.

### Point Claude Code at the central MCP server

The MCP server list lives at `.mcp.json` **inside the checkout you just created**. It's gitignored (it carries your bearer token reference), so copy it from the example that is part of the sparse-checkout and fill in the real hostname:

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

Claude Code expands `${FW_ANALYST_CLIENT_TOKEN}` from your environment — set it in your shell profile or OS keychain, never paste the token into `.mcp.json` itself. Use `https://`, not `http://` — plain HTTP is not acceptable for this data in a regulated environment (NERC CIP, HIPAA, PCI-DSS, etc.). See `docs/workstation-onboarding.md` for the step-by-step setup including how to request your token.

### Verify connectivity

From inside your `4tanalyst-workstation` checkout, start Claude Code and run:

```
/check-policy 10.0.0.1 10.0.0.2 tcp/443
```

If you get a zone policy verdict (ALLOWED / BLOCKED / UNKNOWN), the server is reachable and setup is complete. If you get a connection error, see the Troubleshooting section.

---

## 2. Working a firewall request

### Before you start: classify the request

The first step determines how much work follows.

| Request type | Typical scope | Why it matters |
|---|---|---|
| OT (Operational Technology) | **Multiple firewalls — ~80% of cases** | OT traffic commonly crosses IT/OT boundaries and internal OT segments. Assume multi-firewall until confirmed otherwise. |
| IT (east-west or internet) | Single firewall — ~70-80% of cases | Most IT requests stay within one package or one cluster. |
| IT cross-domain | Multiple firewalls | Internet-facing, DMZ, or cross-datacenter IT flows may still cross multiple devices. |

For OT requests, identify all firewalls in the path before beginning analysis. The system cannot auto-discover the path — you must name the firewalls explicitly when running the skills.

### Step 1 — Parse the intake

If the request arrived as a spreadsheet:

```
/analyze-request
```

Claude Code will prompt you for the file path and extract source, destination, service, requester, and justification. Review the extracted values and correct anything misread before proceeding.

If the request arrived by email or ServiceNow description, provide the details directly when `/analyze-request` prompts for them.

If the request is missing information (no justification, vague services, unknown source system), run:

```
/missing-info
```

This drafts a follow-up message to the requester with the specific gaps. Do not proceed to analysis until the required fields are complete.

### Step 2 — Check zone policy

```
/check-policy <source-IP> <destination-IP> [service]
```

This queries the live 4THealth zone database and returns:

- The resolved zone for each IP
- The policy verdict: ALLOWED, BLOCKED, or UNKNOWN
- A plain-English note explaining the result

**UNKNOWN** from `/check-policy` means the IP could not be resolved to a zone (not registered, recently moved, or in a subnet not yet in 4THealth). Treat UNKNOWN as BLOCKED pending manual verification — never treat it as "probably fine."

Note that the full `/analyze-request` planner handles unresolved IPs differently: they default to the catch-all **Internet** zone (the verdict is then re-derived from the live policy table) and the flow is classified critical risk. The report calls out when this defaulting happened — if the IP is actually internal, get its subnet registered in 4THealth and re-run rather than implementing an Internet-zone rule.

**Zone name mapping:** The zone name returned by `/check-policy` is the 4THealth policy zone name — this may differ from the interface or zone name shown in FortiManager. Translate between policy zones and FortiManager zone names before building rules; a mapping reference is not yet included in this repo. Flag requests where you are unsure and verify manually.

### Step 3 — Search existing rules

```
/analyze-request
```

Within the full analysis flow, Claude Code searches the firewalls you name for existing rules that already match or partially match the request. You must explicitly list the firewalls to check — for example:

> "Check CP-FW-OT-01, CP-FW-IT-EDGE, and FMG-ADOM-GAS for existing rules covering 10.4.10.0/24 to 10.6.0.0/24 on tcp/102."

For OT requests, list all firewalls you identified in Step 0. The system will query each one in parallel.

**Multi-value requests are consolidated.** Give all sources, destinations, and services in one go — the planner makes ONE policy per firewall covering every combination, and only reports "already covered" when *every* source×destination pair is covered by an enabled rule on the flow's actual interfaces. Sides with more than 3 members are put into an address group automatically (`GRP_<ticket>_SRC/DST`); you can also name a group to force grouping for fewer members. If zone policy gives mixed verdicts across the combinations (some allowed, some blocked), the planner refuses and tells you to split the request.

**Option A vs. Option B.** When an existing enabled rule would cover the request except for one address side, and that side references an address group, the analysis presents two mutually exclusive choices: **Option A** — the new consolidated policy, or **Option B** — append the missing endpoint(s) to that group. Option B always comes with the full blast radius: every other rule (in any package, including via nested groups) that would also change. Review that list before choosing B; if any listed rule should *not* gain access to the new endpoints, take Option A.

**Generated artifacts:** at the end of the full `/analyze-request` run, Claude Code writes `report.html` and `implementation.conf` under `output/<ticket-id>/` (or a timestamped folder if you haven't opened a ticket yet). `implementation.conf` contains the exact FortiGate CLI commands to implement the change — or, if the zone verdict is BLOCKED, the exception language and approval placeholders instead. Attach both files to the change ticket; `output/` is gitignored, so these never end up in the repo.

### Step 4 — Validate naming and logging

If you are creating new objects or rules, run:

```
/validate-rule
```

Claude Code checks proposed object names against the naming conventions in `standards_mcp/naming.yaml` and confirms the required log settings for the rule category. Fix any violations before building the rule in the firewall.

### Step 5 — Determine approval chain

The `/analyze-request` output includes the required approvers and change window based on zone risk classification. For OT and CIP-adjacent requests, this will require SecOps sign-off and coordination with OT Operations. For CIP-H zone requests, CISO-level approval and additional regulatory documentation are mandatory (NERC CIP-005 in this environment; substitute your own regime's equivalent if deploying elsewhere) — see `review_requirements.yaml` for the full chain.

### Step 6 — Generate peer review package

```
/generate-peer-review
```

This produces a formatted document containing the full analysis: source/destination, zone resolution, policy verdict, existing rule findings, naming validation, risk classification, and approval chain. The second engineer signs off on this document.

**The peer review package is a draft.** It is a research aid, not an official change record. The reviewing engineer is accountable for verifying its contents before signing. Do not file it as audit evidence without explicit human attestation.

### Step 7 — Record the decision

After the peer review is complete and approvals are obtained, record the outcome:

```
/record-decision
```

This logs the approved/rejected/deferred decision, your engineer ID, the ticket number, and a justification to the feedback store. This record is used to track patterns and improve recommendations over time.

---

## 3. Data flow

This diagram shows how a request moves through the system from intake to decision.

```
Engineer workstation (Claude Code)
        │
        │  MCP streamable-HTTP + bearer token  (read-only, no firewall changes)
        ▼
Central MCP Server (fwanalyst_server, port 8000)
        │
        ├── intake tools
        │     └── Parses .xlsx spreadsheets or manual input
        │           └── Returns structured request fields
        │
        ├── zone tools (live 4THealth)
        │     └── 4THealth external API  ──────────────────▶  4THealth (zone/policy DB)
        │           └── IP → zone resolution
        │           └── Zone pair policy verdict (ALLOWED/BLOCKED/UNKNOWN)
        │
        ├── fortimanager tools
        │     └── FortiManager JSON-RPC API  ─────────────▶  FortiManager (7.4/7.6)
        │           └── Rule search by ADOM
        │           └── Policy package lookups
        │
        ├── standards tools
        │     └── Local files only (no external API calls)
        │           └── naming.yaml  → naming convention rules
        │           └── review_requirements.yaml → approval chains
        │
        └── feedback tools
              └── Local SQLite store
                    └── Records engineer decisions (engineer ID, ticket, outcome)
```

**What flows where:**

- The engineer's laptop never holds credentials or connects directly to FortiManager.
- All firewall API calls originate from the central server using service accounts stored in `credentials.yaml`.
- 4THealth is queried by `zone_mcp` for every IP-to-zone resolution. If 4THealth is unreachable, all zone queries return errors — see Troubleshooting.
- `standards_mcp` reads only local files. It never calls an external API.
- `feedback_mcp` writes to a local SQLite file on the central server. Nothing is sent to ServiceNow automatically.

**Zone name translation:** 4THealth uses policy zone names (e.g., `OT-PROD`, `CIP-HIGH`). FortiManager uses ADOM-scoped zone names. These may differ. When building rules, translate between policy zone names and FortiManager zone names — a mapping reference is not yet included in this repo. Verify zone names manually against the FortiManager GUI.

---

## 4. Troubleshooting

### 4.1 Claude Code cannot connect to an MCP server

**Symptom:** Slash command errors immediately with "MCP server unavailable" or "connection refused."

**Causes and fixes:**

1. Central server is down or the unified service crashed. SSH to the central server and check: `systemctl status 4tanalyst`. Restart if needed.
2. A `401 Unauthorized` means the bearer token in your `mcp_servers.json` is missing, wrong, or revoked — ask the team lead for a new token. If you previously had access to an ADOM and now get `{"error": "ADOM '...' is not in your allowed list."}` from a tool, your token's ADOM scope needs updating — contact the admin (see `SECURITY.md` §"Issuing engineer tokens").
3. Your laptop's `mcp_servers.json` has the wrong hostname or port. Re-read the file and confirm it matches what the team distributed.
4. Firewall between your laptop and the central server is blocking port 8000. Confirm you are on the correct VPN profile or network segment that allows HTTPS to the central server.
5. TLS certificate error (self-signed cert not trusted). Ask your admin for the CA cert and add it to your system trust store, or confirm the server is using a properly signed internal cert.

All tools are served by the single `fwanalyst_server` process — if it is down, nothing works. Individual *backends* can still fail independently (4THealth down but FortiManager up, etc.); those failures come back as explicit typed errors naming the failed source, never as silent empty results.

---

### 4.2 Zone query returns UNKNOWN for a valid IP

**Symptom:** `/check-policy` returns UNKNOWN for an IP you know belongs to a real zone.

**Causes and fixes:**

1. The subnet containing that IP is not yet registered in 4THealth. This is common for recently deployed systems or subnets that pre-date 4THealth adoption. Resolve the zone manually using the network documentation or ask the 4THealth team to add the subnet. Your team owns 4THealth — escalate directly.
2. The IP was recently moved to a new subnet and 4THealth has not been updated. Confirm the current subnet assignment and request a 4THealth update.
3. 4THealth is reachable but its policy database is empty or stale. Run `/check-policy` against a known-good IP (one you have resolved successfully before). If that also returns UNKNOWN, the 4THealth database may need a refresh. Escalate to the 4THealth team.

Never treat UNKNOWN as ALLOWED. Record UNKNOWN in the peer review and resolve it before submitting the change.

---

### 4.3 FortiManager search returns empty or silent errors

**Symptom:** FortiManager queries return no results even for rules you can see in the GUI, or the tool says "success" but returns an empty list.

**Causes and fixes:**

1. Wrong ADOM specified. FortiManager uses ADOMs (Administrative Domains) to partition devices. If you query the wrong ADOM, you will get an empty result without an error. Confirm the ADOM name in FortiManager and re-run.
2. FortiManager silent failures. Some FortiManager API calls return `result: success` with an empty data field when the query finds nothing. The MCP server normalizes this, but if it looks wrong, check FortiManager directly to confirm whether rules exist.
3. API key revoked or regenerated. There is no session to expire — the client authenticates every call with a REST API Administrator Bearer key. A `-22 Login fail` on every call means the key in `credentials.yaml` is stale (regenerated on the FMG side), JSON API Access was disabled on the account, or Trusted Hosts no longer includes the server's IP. See `docs/configuration.md#fortimanager`.
4. Migrating from FortiManager 7.4 to 7.6. During the migration window, API behavior may differ between versions. Note which version you are querying and verify results in the GUI if the API response looks inconsistent.

---

### 4.4 Naming validation flags correct names as violations

**Symptom:** `/validate-rule` rejects a name that matches what the team actually uses.

**Cause:** The naming conventions in `standards_mcp/naming.yaml` contain placeholder values that have not yet been validated against real firewall objects. The tool is enforcing the documented convention, which may not match current practice.

**Fix:** Do not change your rule name to match the tool's output if you know the existing convention is different. Instead:
1. Note the discrepancy in your peer review package.
2. Report it to whoever maintains `naming.yaml` (see CONTRIBUTING.md) with an example of the actual name format in use.
3. Once `naming.yaml` is updated, re-run validation.

The naming conventions are only as good as the data in `naming.yaml`. Until the team has fully validated that file against live objects on FortiManager, treat validation failures as advisory.

---

### 4.5 Peer review generation is incomplete or missing fields

**Symptom:** `/generate-peer-review` output is missing the zone verdict, existing rule findings, or approval chain.

**Cause:** The peer review tool assembles output from earlier steps in the analysis. If any upstream step failed (zone query returned an error, FortiManager search timed out, etc.), those fields will be blank or marked as unavailable.

**Fix:** Re-run the missing steps individually, then re-generate the peer review. If a step cannot be completed (e.g., 4THealth is unreachable), note the gap explicitly in the peer review and document the manual verification you performed as a substitute.

---

### 4.6 Approval chain shows placeholder approver names

**Symptom:** `/analyze-request` returns an approval chain with generic role descriptions like "Network security engineer (peer review)" instead of actual names.

**Cause:** `standards_mcp/review_requirements.yaml` contains role descriptions, not individual approver names. The system does not know who holds each role — it outputs the required roles, not a roster.

**Expected behavior:** This is intentional. You fill in the actual names for each role when you route the change. The tool tells you which roles must sign off; your team's current roster (or your team lead) tells you who fills those roles.

---

### 4.7 All tools work but Claude Code gives incorrect or unexpected analysis

**Symptom:** The zone verdict, risk classification, or recommendations look wrong even though all tools returned results without errors.

**Causes:**

1. Policy verdict reflects intended segmentation policy, not live firewall rules. ALLOWED means the zone policy permits the traffic in principle. It does not mean a rule exists on the firewall, and it does not mean traffic will actually pass.
2. `naming.yaml` or `review_requirements.yaml` contains stale or placeholder values that are producing incorrect validations or approval chains.
3. The 4THealth zone database has a stale subnet assignment for an IP. An IP that moved to a new zone recently may still resolve to the old zone.

In all cases: the engineer is accountable. Use the tool output as a research starting point, verify anything that looks wrong against the authoritative source (FortiManager GUI, network documentation), and document your verification in the peer review.

---

## Quick reference

| Command | When to use |
|---|---|
| `/analyze-request` | Start of every request — full analysis workflow |
| `/check-policy <src> <dst> [svc]` | Quick zone verdict without full analysis |
| `/validate-rule` | Before building objects/rules — naming and logging check |
| `/generate-peer-review` | After analysis is complete — assembles sign-off document |
| `/record-decision` | After approvals obtained — logs outcome to feedback store |
| `/missing-info` | Request is incomplete — drafts follow-up to requester |
