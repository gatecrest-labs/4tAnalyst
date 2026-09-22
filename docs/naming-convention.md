# Org-Specific Naming Conventions

4tAnalyst ships with a generic `naming.yaml` containing neutral placeholder examples. Before going live, replace it with your organisation's real conventions by creating `standards_mcp/naming.local.yaml`. This file is **gitignored** — it will never be committed to GitLab or GitHub.

## How it works

When the server starts, it looks for files in this order:

1. `STANDARDS_NAMING_YAML` environment variable (explicit path — highest priority)
2. `standards_mcp/naming.local.yaml` (org-specific override — auto-detected, **gitignored**)
3. `standards_mcp/naming.yaml` (generic default — ships with the repo)

The first file found is loaded in full. There is no merging — the override completely replaces the default.

## Generating your `naming.local.yaml` with AI

You likely already have a naming convention document: a Word doc, PDF, or screenshot from your network or security team. Use Claude to read it and produce the YAML file.

### Step 1 — Open Claude (or Claude Code)

You need Claude with file or image input capability. Claude.ai with a Pro/Max subscription works, as does Claude Code on your workstation.

### Step 2 — Paste this prompt

Copy the prompt below and attach your naming convention document (Word, PDF, or image/screenshot). Claude will produce a ready-to-save `naming.local.yaml`.

---

```
I am setting up 4tAnalyst, a firewall rule request analysis tool that uses a YAML file
to enforce naming conventions for FortiGate objects managed by FortiManager.

Attached is [our naming convention policy document / a screenshot of our naming standards].
Please read it and generate a complete `naming.local.yaml` file for 4tAnalyst.

The file must follow this exact schema (do not add or remove top-level keys):

  platforms:
    fortigate:
      conventions:
        host:
          pattern: "..."        # naming pattern, using <PLACEHOLDERS> in angle brackets
          examples:
            - "..."
          notes: >
            ...
        network:
          pattern: "..."
          examples: [...]
          notes: >  ...
        range:      { pattern, examples, notes }
        address_group: { pattern, examples, notes }
        fqdn_address:  { pattern, examples, notes }
        wildcard_fqdn_address: { pattern, examples, notes }
        fqdn_destination_group: { pattern, examples, notes }
        service:       { pattern, examples, notes }
        service_group: { pattern, examples, notes }
        policy:        { pattern, examples, notes }
        nat_rule:      { pattern, examples, notes }
        vip:           { pattern, examples, notes }

  zone_abbrevs:
    "Full Zone Name As Used In FortiManager": "ABBREV"
    ...

  log_settings:
    allow_internet_inbound:  { log_start, log_end, alert_on_match, retention_days, siem_forward, notes }
    allow_internet_outbound: { ... }
    allow_internal:          { ... }
    allow_ot_to_it:          { ... }
    allow_it_to_ot:          { ... }
    block_all:               { ... }
    block_specific_service:  { ... }
    nat:                     { ... }
    management_access:       { ... }

Rules:
- Use your best judgment for any section the document does not explicitly cover.
- Add a YAML comment on any section where you made an assumption.
- Do not invent zone names — use only what appears in the document.
- The file goes in standards_mcp/naming.local.yaml relative to the repo root.
```

---

### Step 3 — Save the output

Copy Claude's output and save it as `standards_mcp/naming.local.yaml` in your 4tAnalyst server deployment directory.

### Step 4 — Verify the file is ignored

Run this from the repo root to confirm git will never track the file:

```bash
git check-ignore -v standards_mcp/naming.local.yaml
```

Expected output:
```
.gitignore:15:standards_mcp/naming.local.yaml   standards_mcp/naming.local.yaml
```

If the command returns nothing, the file is **not** ignored — check that `.gitignore` contains the line `standards_mcp/naming.local.yaml`.

Also confirm it does not appear in `git status`:

```bash
git status
```

`naming.local.yaml` should not appear in the output at all.

### Step 5 — Restart the server

The naming data is loaded once at startup and cached. Restart the 4tAnalyst server process (or container) to pick up the new file:

```bash
# systemd
sudo systemctl restart 4tanalyst

# Docker Compose
docker compose restart

# Direct uvicorn (development)
# Stop and re-run: MCP_TRANSPORT=http ... uv run python -m fwanalyst_server
```

On startup you will see a log line:
```
standards: loading org-specific naming conventions from .../naming.local.yaml
```

## Updating conventions later

Edit `naming.local.yaml` directly on the server and restart. For large changes, feed the updated policy document back to Claude with the same prompt above.

If a new version of 4tAnalyst adds object types to `naming.yaml`, compare the two files and add any missing sections to your `naming.local.yaml`.

## Reverting to defaults

Delete or rename `naming.local.yaml` and restart the server. The generic `naming.yaml` will be used automatically.

## Environment variable override (advanced)

For containerised or multi-environment deployments where you want to keep the naming file outside the repo directory entirely:

```bash
export STANDARDS_NAMING_YAML=/etc/4tanalyst/naming.yaml
```

This takes precedence over `naming.local.yaml`.
