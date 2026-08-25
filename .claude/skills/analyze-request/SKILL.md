---
name: analyze-request
description: Analyze a firewall change request end-to-end — zone policy verdict, existing rule search on named firewalls, naming/logging validation, and approval chain. Primary engineer workflow tool.
---

# Analyze Firewall Change Request

## Purpose
Full analysis of a firewall change request. All analysis is computed by the
deterministic planner (`plan_change` tool) — zone verdict, existing-rule
coverage, object reuse, rule insertion point, naming/logging, approval chain,
and FortiGate CLI. Your job is to collect the inputs, call the tool, present
its output faithfully, and answer follow-up questions.

**You must never recompute, second-guess, or edit anything the planner
returns** — not verdicts, not object names, not CLI text, not insertion
points. If something looks wrong, say so to the engineer and flag it with
`flag_for_review`; do not "fix" it yourself.

> **Workstation mode:** All analysis steps use MCP tools exclusively via the `4tanalyst` MCP server. Do NOT attempt to install packages or import MCP modules locally. The one exception is Step 4: `scripts/render_report.py` is stdlib-only and MUST be run locally with `python3` to write the report files to the engineer's workstation.

## Workflow

### Step 1 — Gather request details
If the user hasn't provided all of the following, ask for them before proceeding:
- **Source IPs/CIDRs** (one or more)
- **Destination IPs/CIDRs** (one or more)
- **Service(s)** — port, port name, or proto/port (e.g. 443, ssh, tcp/8443)
- **Business justification** — what system/application needs this and why
- **Firewalls to be modified, with their ADOM** — the engineer must name
  these explicitly (e.g. "SITE01-FW01 in OT-ADOM"). We do not auto-discover
  the path. If the engineer doesn't know the ADOM, use `get_adoms()` /
  `get_devices(adom)` to locate the device and confirm with them.
- **Ticket ID** (optional) — becomes the output folder name in Step 4;
  without it the render script uses a timestamp folder.

If the request arrived as a spreadsheet, run `parse_spreadsheet_file` first
and check `missing_fields`/`warnings` before proceeding (see /missing-info).

### Step 2 — Call the planner
Call `plan_change` **ONCE for the whole request** — pass every source,
destination, and service together (comma-separated strings). The engine
plans one consolidated policy per firewall, auto-grouping sides with more
than 3 members. Never split a request into per-pair calls yourself.

```
plan_change(
    src="<src1>, <src2>, ...", dst="<dst1>, ...",
    service="<svc1>, <svc2>, ...",
    firewalls=["DEVICE:ADOM", ...],
    justification=<justification>, ticket_id=<ticket or "">,
    src_group="<name>",  # optional — only if the engineer wants a named group
    dst_group="<name>",  # optional
)
```

The result is the complete report payload. If it contains a top-level
`error`, relay it verbatim — `error_source` says which system failed
(fortimanager / 4thealth / credentials / request). A mixed-verdict error
(some combinations ALLOWED, some BLOCKED) means the request must be split;
relay the message and ask the engineer how to proceed.

### Step 3 — Present the result
Present the payload's sections in this order, verbatim (reformat into
tables/headers, but never alter values). Deduplicate by src×dst×service — do not repeat a row already shown.

1. **Warnings first** — if `warnings` mentions degraded FortiManager data,
   lead with it: coverage conclusions are not trustworthy until re-run.
2. **Zone Policy Verdict** — verdict, src/dst zones, governing policies.
3. **Existing Rules on Named Firewalls** — per-firewall status and rules.
   If a firewall shows NOT FOUND / ERROR, say so clearly — never skip it.
4. **Object Naming** — reused vs. created objects.
5. **Logging Requirements** and **Approval Requirements** as returned.
6. **Placement** — each per-firewall warning starting with "Placement:"
   explains where the new rule must sit and why; surface it prominently.
7. **Alternative (if present)** — when a per-firewall entry contains an
   `alternative`, the planner found a near-miss rule that would cover the
   flow if the missing endpoint(s) were appended to a group it already
   references.
   Present it as **Option B** next to the new-policy plan (**Option A**),
   including the full `affected_rules` list — every other rule that
   references the group and would also change. Make clear the engineer
   must choose ONE option. Never present the group append without its
   affected-rules list.
8. **Recommendation** — quote the planner's recommendation text.

**If `plan_change` fails (connection drop or timeout):** Retry once. If it fails again, save any completed results, document the pending work clearly in the conversation, and ask the engineer to verify the server is up (`docker compose ps` or `systemctl status 4tanalyst`). As a fallback when the MCP server is unreachable, the planner can be run directly on the server: `uv run python -m planner --src <src> --dst <dsts> --service <svc> --firewall <fw:adom> --ticket <ticket>`.

### Step 4 — Generate artifacts
Determine the output subdirectory name: use the ticket_id from the payload if
present, otherwise use today's date+time in `YYYY-MM-DD_HHMM` format (match
what `render_report.output_dir_name()` would produce).

Write the payload JSON to `output/<subdir>/payload.json` first (not a temp
file — this preserves the raw planner data for inspection alongside the
report). Then run:

```
uv run python scripts/render_report.py --data output/<subdir>/payload.json --outdir output/ \
  --model "<active-model-name>" --cost-usd "<estimated-cost>"
```

Replace `<active-model-name>` with the model powering this session (e.g. `"Claude Sonnet 5"`, `"Claude Opus 5"`) — visible in the Claude Code status bar or `/config`. Replace `<estimated-cost>` with a rough USD estimate for this session (e.g. `"0.08"` for a typical single-firewall analysis at Sonnet pricing; omit the flag entirely if unknown).

It prints the `report.html` and `implementation.conf` paths on success.
Tell the engineer:
> Report and CLI config saved to `output/<ticket-or-timestamp>/` — attach
> both to the change ticket.

`render_report.py` will overwrite `payload.json` with a re-saved copy (same
data), so the final directory always contains all three files.

(fgplanner also ships its own standalone CLI, but it ships no default
FortiManager/zone-policy clients and reads no credentials file by design —
`fwanalyst_server/server.py` is what wires it to `credentials.yaml` here.
Running `python -m fgplanner ...` directly from this repo without separately
registering client factories will fail with "no FortiManager client
configured"; the `plan_change` MCP tool above is the wired path.)

### Step 5 — Record the outcome
After the engineer decides, use /record-decision (feedback tools) so the
audit trail and precedent database stay current.

## Notes
- Never auto-discover firewall path — always require the engineer to name devices
- Zone verdict UNKNOWN → the planner refuses to generate CLI; ask the
  engineer to verify the IPs or get the 4THealth zone catalogue updated
- `check_ip_traffic` (zone tools) remains available for quick ad-hoc checks
  (/check-policy); `standards` `check_traffic` is static TUFIN-era data —
  never use it for verdicts
- The zone policy verdict reflects *intended* segmentation policy; existing
  firewall rules may implement or contradict it — the planner reports both
