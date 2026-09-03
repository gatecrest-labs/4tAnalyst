---
name: analyze-hygiene
description: Turn a completed Rule Hygiene run's findings (JSON/CSV export or scheduled-job attachment) into deterministic FortiGate CLI remediation per finding, with a self-contained HTML report, for a single firewall and policy package.
---

# Analyze Rule Hygiene Findings

## Purpose

Turn a completed Rule Hygiene run (from the companion 4thealth-plus app)
into concrete, per-finding FortiGate CLI remediation for one firewall
policy package. All matching and fix generation is computed
deterministically by `hygiene.engine.assess()` — your job is to collect the
input, call the tools, and present the result faithfully.

**You must never recompute, second-guess, or edit anything
`assess_hygiene_fixes` returns** — not a fix option, not the CLI, not a
stale-finding determination. If something looks wrong, say so to the
engineer; do not "fix" it yourself.

## Workflow

### Step 1 — Get the findings and their scope
Ask the engineer for:
- The hygiene findings: pasted JSON or CSV text, or a file path to upload.
- Which **ADOM**, **device**, and **policy package** the hygiene run was
  against — the export itself doesn't carry this, so it must be supplied.

### Step 2 — Parse the findings
```
parse_hygiene_findings(text=<pasted text or "">,
                        file_content=<file text or "">,
                        file_type="json" | "csv")
```
If it returns `{"error": ...}`, tell the engineer what's wrong (malformed
JSON, no recognizable CSV header) and ask them to re-paste/re-upload — never
guess at a shape to make the call succeed.

### Step 3 — Assess fixes
```
assess_hygiene_fixes(adom=<adom>, device=<device>, pkg=<package>,
                      findings=<the findings list from Step 2>)
```
This re-fetches the live policy package (scoped to that one package) and
cross-references it against the findings. Returns:
- `fixes` — per-finding remediation options (check, policy name/id, CLI)
- `stale_findings` — findings whose policy_id no longer exists in the live
  package, with a reason
- `html_content` — the full HTML report as a string (write this to disk)
- `html_error` — set if rendering failed (call `render_hygiene_report` to
  retry)

If it returns `{"error": ...}` (e.g. `error_code: "forbidden"` for an ADOM
the engineer's token can't access, or `"upstream_error"` if the live-policy
fetch failed), report it plainly — don't retry with a guessed value.

### Step 4 — Write the HTML report locally
```
Write(
  file_path="output/hygiene/<device>_<pkg>_<YYYY-MM-DD>.html",
  content=<html_content from Step 3>
)
```
Use today's date. Create the directory if needed. Report the saved path to
the engineer.

If `html_error` is set instead, call `render_hygiene_report` to retry (see
Step 6), then write its `html_content`.

### Step 5 — Present the result
Present in this order, verbatim (reformat into tables/headers, never alter
values):
1. **Stale findings first**, if any — these were skipped; list them with
   their reasons.
2. **Counts by check** — how many findings per check type.
3. **Any irreversible option** — the `disabled` check's >90-day `delete`
   fix. Call these out explicitly since they're not undoable.
4. **Local HTML report path** — the path from Step 4.
5. Mention `/record-decision` as the next step if the engineer applies any
   of the generated fixes.

### Step 6 — Re-render (only if Step 3's html_error is set)
```
render_hygiene_report(assessment=<the fixes/stale_findings/device/adom/pkg/
                                   generated_at structure from Step 3>)
```
Then Write the returned `html_content` locally as in Step 4.
