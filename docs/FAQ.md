# Frequently Asked Questions

---

## Setup and access

**Do I need to install Python, credentials, or MCP server packages on my laptop?**

No. The only things you need locally are Claude Code and the sparse checkout of this repo (`.claude/` skills and the `scripts/` render script). All server-side processing — FortiManager queries, zone verdicts, policy evaluation — runs on the central server. Your laptop never holds API keys and never connects to FortiManager directly.

**How do I get access?**

Contact the FW engineering team lead to request a bearer token. Let them know which ADOMs you need access to. See `docs/workstation-onboarding.md` for the full step-by-step.

**I can't connect to the MCP server. What do I check first?**

1. Confirm `FW_ANALYST_CLIENT_TOKEN` is set in your shell environment (`echo $FW_ANALYST_CLIENT_TOKEN`).
2. Check that `.mcp.json` in the repo root uses `${FW_ANALYST_CLIENT_TOKEN}` (not a hardcoded placeholder).
3. Confirm the URL matches what the admin gave you — no stray `:8000` port if the server is behind nginx on 443.
4. Verify the server is running: `systemctl status 4tanalyst` on the central server (or ask the admin).

See `docs/engineer-workflow.md` §4 for the full troubleshooting guide.

**I'm getting a `401 Unauthorized`.**

Your token is missing, wrong, or revoked. Double-check `FW_ANALYST_CLIENT_TOKEN` in your environment. If it looks correct, contact the admin — tokens can be revoked and re-issued without a server restart.

**I'm getting `ADOM 'X' is not in your allowed list`.**

Your token is scoped to a different set of ADOMs than the one you requested. Contact the admin to expand your ADOM access.

---

## Understanding results

**ALLOWED verdict — does that mean a firewall rule already exists?**

No. ALLOWED means the zone segmentation policy *permits* the traffic in principle. It does not mean a rule is already configured on the firewall. Use `/analyze-request` to check whether an existing rule covers the flow on the specific devices.

**`/check-policy` returns UNKNOWN for an IP I know is internal. What's wrong?**

The subnet for that IP is probably not registered in 4THealth, or was recently moved and 4THealth hasn't been updated. UNKNOWN is not the same as ALLOWED — treat it as denied until you resolve the zone manually. Contact the 4THealth team to add or correct the subnet. See `docs/engineer-workflow.md` §4.2.

**The full `/analyze-request` planner treats UNKNOWN IPs differently — why?**

`/check-policy` queries 4THealth directly and returns UNKNOWN when it can't match the IP. The planner (`/analyze-request`) goes one step further: an unresolved IP is assigned to the catch-all **Internet** zone, the verdict is re-derived from the live policy table, and the risk is classified as critical. This is a safety default — the report flags it explicitly. If the IP is actually internal, get it registered in 4THealth and re-run rather than implementing a rule scoped to the Internet zone.

**What does "degraded" mean in the output?**

A data source (FortiManager for a specific ADOM or device) failed to respond during the analysis. Degraded results are explicitly called out and never silently treated as "no result." In the planner, a degraded device is never reported as "already covered" — the absence of a result is not the same as confirmed coverage. Fix the connectivity issue and re-run.

**The analysis says the request is "already covered" — can I trust that?**

Yes, with one caveat: "already covered" means every source×destination pair in the request is covered by an **enabled, non-conditional, non-degraded** rule on the flow's actual interfaces. If any device snapshot was degraded, the planner will say so and withhold the "already covered" verdict for that device. If you see unexpected results, verify in the FortiManager GUI.

**What's the difference between ALLOWED and BLOCKED in `/check-policy` vs. the full analysis?**

`/check-policy` gives you the zone-pair policy verdict from 4THealth (is this traffic class *intended* to be permitted?). The full `/analyze-request` also checks whether a rule *actually exists* on the specific firewalls to implement that intent. A flow can be ALLOWED by policy but still blocked in practice if no rule has been created yet.

---

## Firewall topology

**Why do I have to name the firewalls manually? Can't the tool figure that out?**

Automatic path discovery requires a complete network topology source — that's what NetBrain would provide. NetBrain API access is not yet available. Until it is, engineers declare the firewalls explicitly. This is a deliberate choice: explicit is more reliable than guessed, and engineers generally know which devices are in path for their environment. The planner then queries only those named devices.

**How do I know which firewalls are in path for an OT request?**

For OT requests, ~80% of cases involve multiple firewalls crossing IT/OT boundaries. Identify all devices in path using network diagrams or by consulting the network team before running the analysis. If you're unsure, `/check-policy` can help you confirm which zone each IP belongs to, which often narrows down the relevant firewall cluster.

---

## Naming and logging

**Naming validation is flagging names I know are correct. What do I do?**

`standards_mcp/naming.yaml` may contain placeholder values that don't yet reflect your team's actual conventions. Do not change your rule name to match the tool — instead, note the discrepancy in your peer review package and report it to whoever maintains `naming.yaml` (see `CONTRIBUTING.md`). Until the file is fully validated against live FortiManager objects, treat validation failures as advisory. See `docs/engineer-workflow.md` §4.4.

**The approval chain shows generic role descriptions, not actual names.**

That's expected. `review_requirements.yaml` captures required *roles* (e.g., "Network security engineer (peer review)"), not a personnel roster. You fill in the actual names when routing the change. See `docs/engineer-workflow.md` §4.6.

---

## Output files

**Where do the generated report files go?**

`report.html` and `implementation.conf` are saved under `output/<ticket-id>/` in your local checkout (or a timestamped folder if you haven't set a ticket ID). The `output/` directory is gitignored — files there are never committed to the repo. PSIRT reports go to `output/PSIRT/<advisory-id>/`; hygiene reports go to `output/hygiene/`.

**Should I attach the `implementation.conf` file to my change ticket?**

Yes — attach both `report.html` and `implementation.conf` to the change ticket before submission. `implementation.conf` contains the exact FortiGate CLI to implement the change (or the exception language and placeholders if the verdict is BLOCKED). The peer review process assumes reviewers have both files.

---

## PSIRT advisories

**How do I assess a Fortinet security advisory against the fleet?**

Run `/analyze-psirt` and paste the advisory email text when prompted. Claude extracts the affected version ranges, queries FortiManager for all devices' running versions, and produces a per-device verdict (no_action / config_change_required / upgrade_required) plus an HTML report. No manual version lookups needed. See `docs/usage.md` for full details.

**Why is priority flagged as High when the CVSS score is Medium?**

Priority is exploit-aware. If the vulnerability appears in the CISA Known Exploited Vulnerabilities (KEV) catalog, or if Fortinet's own advisory mentions exploitation in the wild, priority is forced to at least High regardless of CVSS. A CVE being actively exploited is more urgent than its theoretical severity score suggests.

**What does `manual_verification_required` mean for a workaround?**

The tool only checks workaround patterns it explicitly recognizes (e.g., restricting admin-access interfaces). If the advisory's workaround text doesn't match a known pattern, the tool returns `manual_verification_required` rather than guessing. Treat it as `config_change_required` until you verify the workaround status manually on the device.

---

## Rule Hygiene

**How do I use the hygiene analysis?**

Run `/analyze-hygiene` after exporting findings from the FortiManager Rule Hygiene module (JSON or CSV format). Claude will prompt you for the findings and the ADOM/device/package scope, then produce per-finding FortiGate CLI remediation and an HTML report. See `docs/usage.md` for full details including the fix types supported.

**What are "stale findings"?**

A finding is stale when the `policy_id` from the hygiene export no longer exists in the live policy package fetched from FortiManager. This usually means the rule was already fixed or deleted since the hygiene run. Stale findings are listed separately at the top of the output. Verify manually that the rule was intentionally removed before treating them as resolved.

---

## Running without the AI path

**Can this tool be used without Claude?**

Yes. The deterministic planner (`fgplanner`) is a standalone Python CLI that doesn't require an LLM. It's the same engine that runs inside the MCP server:

```bash
python -m fgplanner --src 10.1.2.3 --dst 10.9.8.7 --service tcp/8443 \
    --firewall MNHQ-FW01:OT-ADOM --ticket CHG0012345
```

This matters in regulated environments where the AI inference path may require separate compliance approval — the deterministic tool can be approved independently. See `docs/architecture.md` for the full discussion.

**Can the tool make changes to the firewall automatically?**

No. All MCP tools are read-only. The tool produces FortiGate CLI commands and an HTML report for human review; engineers copy and apply the CLI during the approved change window. This is by design — `docs/architecture.md` covers the rationale under "Read-only MCP tools throughout."
