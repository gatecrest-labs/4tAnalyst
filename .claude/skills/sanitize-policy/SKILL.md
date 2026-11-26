---
name: sanitize-policy
description: Sanitize a Rule Review policy JSON export locally (offline, stdlib-only) so it can be reviewed with /review-policy. The raw export is never read by Claude.
---

# Sanitize a Policy Export

## Purpose

Replace real identifiers (IPv4/IPv6 addresses, hostnames, site/company terms)
in a Rule Review policy JSON export with consistent fake placeholders,
entirely on the engineer's workstation, so the sanitized copy can be handed to
`/review-policy`. The real-to-fake map stays local and is never shown.

**The raw export is sensitive. You must never Read, cat, head, grep, or open
it with any tool.** Only the CLI touches it. Do not run commands that print
file contents (no `cat`, `head`, `tail`, `grep`, `less`, `ls` on content).
Likewise, never Read, cat, or list the map directory (`~/.local/share/4tanalyst/sanitize/`) or its files, and never print the terms file's contents (existence check with `test -f` only). If the CLI fails, relay its message verbatim; never try to debug by reading
the raw input.

**Never move, copy, or rename the raw export yourself** (no `mv`, `cp`,
`rename`, or any other tool). The ENGINEER moves or renames it; you only tell
them what to do.

## Recommended hardening (the engineer's own settings)

Engineers should add deny rules to their OWN user-level Claude settings
(`~/.claude/settings.json`) so the raw exports, the local map store, the
terms/config directory and the map-back output folder can never be read even
by mistake:

```json
{
  "permissions": {
    "deny": ["Read(~/policy-exports/**)", "Read(~/.local/share/4tanalyst/**)", "Read(~/.config/4tanalyst/**)", "Read(~/policy-mapped/**)"]
  }
}
```

This skill and the implementation never edit settings files; the engineer
does this themselves.

## Workflow

### Step 1 — Get a neutrally named export path
The 4thealth export is named after the real policy package, so its file name
is itself sensitive. Before giving you the path, the engineer must:

1. save the export under `~/policy-exports/`, and
2. rename it to a neutral name `export-<anything>.json`, for example
   `~/policy-exports/export-1.json`.

Ask for the path. Check the basename against the regex
`^export-[A-Za-z0-9_-]*\.json$` and check that it is under `~/policy-exports/`.
If either check fails, **STOP**: tell the engineer to move and/or rename the
file themselves (to `~/policy-exports/export-<anything>.json`) and give you
the new path. Do not repeat the original file name back, do not quote it, and
do not move or rename the file yourself. Do not open it.

Refuse any `--input` under `~/policy-mapped/` (map-back output with REAL
values) or under `~/policy-sanitized/` / `output/` (already sanitized), even
if the name matches.

### Step 2 — Check the terms file
Terms file: `~/.config/4tanalyst/sanitize-terms.txt`. Check existence only,
with `test -f ~/.config/4tanalyst/sanitize-terms.txt`; never print its
contents. Format: one literal, case-insensitive term per line, optional
`term=PLACEHOLDER`, `#` for comments. Terms of 4 or more characters are
matched anywhere, even inside longer words (`acme` also scrubs
`acmecorp-fw`); shorter terms match only as whole tokens. Example (invented
values):

```
# company and site terms to scrub
acme
acme-hq=SITE_A
```

If missing, tell the engineer to create it (or pass `--no-terms` if they
accept IP/host-only sanitizing).

### Step 3 — Run the CLI
```
uv run python -m policy_sanitize sanitize --input ~/policy-exports/export-1.json \
    --out-dir ~/policy-sanitized [--terms PATH | --no-terms] [--strict]
```
Use the engineer's neutral `export-*.json` path. The output dir must NOT be under `~/policy-exports/` and must not be inside the repo or a OneDrive/CloudStorage path; use `~/policy-sanitized/`. `--input` may be repeated (every input must be an `export-*.json` name). Recommend `--strict` for production use.

### Step 4 — Relay only CLI output
Relay only the CLI's stdout/stderr lines (`run-id:`, `output:`, `rules:`,
`replaced:`, `unmatched-identifiers:`, `verifier: clean`, `map: stored (not
shown)`) and the sanitized output path(s). Nothing else.

Exit codes:
- `0` — success.
- `2` — bad input, bad terms file, collision, or internal error. Relay the message verbatim.
- `3` — the verifier found a leak. Do NOT use the output; report it and stop.
- `4` — `--strict` and unmatched identifiers remain. Nothing was written.

A non-zero `unmatched-identifiers` count means identifiers that mix letters
and digits (for example a device name like `fw01`) were left that no term
covers: tell the engineer to review and extend the terms file, then re-run
**before** `/review-policy`.

### Step 5 — Next step
Tell the engineer to run `/review-policy <sanitized path>`.

## Map-back and purge (local, by the engineer)

```
uv run python -m policy_sanitize map-back --run-id <ID> \
    --input output/policy-review/policy-review-<ID>.html \
    --output ~/policy-mapped/policy-review-<ID>.html
uv run python -m policy_sanitize purge
```
**The mapped output contains REAL values and must never be pasted into
Claude.** Everything under `~/policy-mapped/` holds REAL values: never read,
cat, list, or open anything there. The CLI refuses output paths inside the repo or OneDrive. Maps are
stored in `~/.local/share/4tanalyst/sanitize/`; `purge` removes expired maps
(older than 30 days).
