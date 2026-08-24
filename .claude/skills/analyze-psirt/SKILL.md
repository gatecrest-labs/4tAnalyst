---
name: analyze-psirt
description: Assess a Fortinet PSIRT advisory email against the live fleet (FortiGate + FortiManager) — per-device no-action/config-change/upgrade verdicts, exploit-aware priority, HTML report.
---

# Analyze PSIRT Advisory

## Purpose

Turn a Fortinet PSIRT advisory notification email into a concrete,
per-device disposition across the fleet. All matching, scoring, and
verdicts are computed deterministically by `psirt.engine.assess()` — your
job is to extract structured fields from the email, call the tools, and
present the result faithfully.

**You must never recompute, second-guess, or edit anything
`assess_fleet_exposure` returns** — not the verdict, not the priority, not
the workaround status. If something looks wrong, say so to the engineer
and flag it with `flag_for_review`; do not "fix" it yourself.

## Workflow

### Step 1 — Get the advisory email
Ask the engineer to paste the PSIRT email text, or give you a `.eml` file
path, if they haven't already.

### Step 2 — Extract structured fields yourself
Read the email/eml content and extract:
- `advisory_id` — Fortinet's advisory ID (e.g. `FG-IR-24-001`)
- `advisory_url` — link to the fortiguard.com advisory page, if present
- `cve_ids` — list of CVE identifiers (format `CVE-YYYY-NNNN`)
- `published_date`, `fortinet_severity`, `cvss_score` (float, if stated)
- `description` — one-line summary of the vulnerability
- `affected_ranges` — list of `{product, min_version, max_version,
  fixed_version, notes}`. `product` should be `"FortiOS"` or
  `"FortiManager"` for anything you want matched against the fleet — use
  the exact product name from the email for anything else (it will be
  reported as out-of-scope, not silently dropped). Leave `min_version`/
  `max_version` empty for an open-ended bound (e.g. "7.4.0 and below" →
  `min_version=""`, `max_version="7.4.0"`).
- `workaround_text` — the vendor's workaround/mitigation text, verbatim,
  if any
- `exploited_in_wild_text` — Fortinet's own exploitation language,
  verbatim, if any (empty string if the advisory doesn't mention it)

Do not guess at a value you can't find in the email — leave it empty/None
and let `parse_advisory` and the assessment surface it as missing.

### Step 3 — Call parse_advisory
```
parse_advisory(email_text=<pasted text or "">, eml_path=<path or "">,
                extracted={...the fields from Step 2...})
```
If it returns `{"error": ...}`, tell the engineer what's missing and ask
for it — never invent a value to make the call succeed.

### Step 4 — Call assess_fleet_exposure
```
assess_fleet_exposure(advisory=<the dict parse_advisory returned>)
```

`assess_fleet_exposure` runs the full fleet assessment on the server and
returns a compact summary dict plus the rendered HTML as a string:
- `html_content` — the full HTML report as a string (write this to disk locally)
- `html_error` — set if rendering failed (call `render_psirt_report` to retry)
- `verdict_counts` — dict of verdict → device count
- `total_findings`, `priority`, `priority_rationale`, `kev_hit`, `degraded`, `warnings`

### Step 5 — Write the HTML report locally
Use the Write tool to save `html_content` to the local workstation:
```
Write(
  file_path="output/PSIRT/<advisory_id>/<advisory_id>.html",
  content=<html_content from Step 4>
)
```
Create the directory if needed. Report the saved path to the engineer.

If `html_error` is set instead, call `render_psirt_report` to retry (see Step 6).

### Step 6 — Present the result
Present in this order, verbatim (reformat into tables/headers, never alter
values):
1. **Warnings first** — if `warnings` is non-empty or `degraded` is true,
   lead with it: some devices may not have been fully checked.
2. **Priority** — `priority` and `priority_rationale`, and call out
   `kev_hit` prominently if true.
3. **Fleet summary** — `verdict_counts` table and `total_findings`.
   If `verdict_counts` has any `upgrade_required` or `config_change_required`
   entries, also list those specific devices by reading the HTML report.
4. **Local HTML report path** — show the path you wrote in Step 5.

### Step 7 — Re-render (only if Step 4 html_error is set)
If `assess_fleet_exposure` returned `html_error`, retry with the inline
assessment. **Do not pass the full findings list** — use the compact
summary returned by Step 4:
```
render_psirt_report(assessment=<the advisory/priority/findings structure>)
```
Then Write the returned `html_content` locally as in Step 5.

### Step 8 — Record the decision
For each device with a non-`no_action` verdict (or on engineer request for
all), call `record_feedback` with:
- `request_id` = the advisory ID
- `recommendation_id` = `"<advisory_id>-<device>"`
- `decision` = one of `ACCEPTED`/`MODIFIED`/`REJECTED` per the engineer's
  actual disposition (ask them — do not assume ACCEPTED)
- `recommendation_json` = the device's finding as JSON
- `platform` = `"FortiOS"` or `"FortiManager"`
