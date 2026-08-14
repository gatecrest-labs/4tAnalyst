# 4tAnalyst Workstation Onboarding

One page to get a firewall engineer's laptop working. If you're deploying or maintaining the *server*, see `docs/installation.md` and `docs/engineer-workflow.md` §1 instead — this page is checkout/verify steps only.

You never install Python, credentials, or MCP server packages locally, and you never handle FortiManager/4THealth API keys — those live only on the central server (see `SECURITY.md`).

## 1. Get a slim checkout

A sparse checkout pulls down only the slash commands and the local report-rendering script — not the server packages, tests, or docs you don't need on a laptop:

```bash
git clone --filter=blob:none --sparse <repo-url> 4tAnalyst-workstation
cd 4tAnalyst-workstation
git sparse-checkout set --no-cone .claude/ scripts/ .mcp.json.example
```

Your team access to this repo is **read-only**. If you spot a bug in a skill or a naming rule it enforces, report it to the FW engineering team (see `CONTRIBUTING.md`) rather than editing your local copy.

To pick up later updates (new/changed skills, render-script fixes):

```bash
git pull
```

## 2. Install Claude Code

Install from [claude.ai/code](https://claude.ai/code). You need an Anthropic subscription (Claude Max or API access) — confirm with IT that your account is provisioned first.

## 3. Request your bearer token from the admin

Each engineer gets their own bearer token scoped to the ADOMs they need. Contact the FW engineering team lead and ask for a **4tAnalyst bearer token**. Let them know which ADOMs you need access to (e.g., "OT-ADOM and GAS-ADOM" or "all ADOMs"). They will generate the token and send it to you over a secure channel.

The token is a random hex string (64 characters). Treat it as a password:
- Do not email it in plaintext or paste it into Teams/Slack without encryption
- Do not commit it to any file in the repo
- If you suspect it was exposed, contact the admin immediately to rotate it

You will put this token into the `.mcp.json` file in the next step.

> **Admins:** see the **Issuing engineer tokens** section in `SECURITY.md` for the provisioning procedure.

## 4. Point Claude Code at the central server

Copy the example config and fill in your hostname:

```bash
cp .mcp.json.example .mcp.json
```

Then edit `.mcp.json` and replace the one remaining placeholder:

```json
{
  "mcpServers": {
    "4tanalyst": {
      "type": "http",
      "url": "https://<central-server>:8000/mcp",
      "headers": {
        "Authorization": "Bearer ${FW_ANALYST_CLIENT_TOKEN}"
      }
    }
  }
}
```

Replace `<central-server>` with the hostname the admin provides. Use `https://`, not `http://` — plain HTTP is not acceptable for this data in a regulated environment (NERC CIP, HIPAA, PCI-DSS, etc.).

Do **not** paste the token itself into `.mcp.json`. Claude Code expands `${VAR}` references in `.mcp.json` headers at connect time, so set `FW_ANALYST_CLIENT_TOKEN` as an environment variable instead — in your shell profile (`~/.zshrc`, `~/.bashrc`) or, better, your OS keychain if your shell setup supports sourcing secrets from it:

```bash
export FW_ANALYST_CLIENT_TOKEN="<the 64-character token from Step 3>"
```

The token handling rules from Step 3 still apply — do not email it in plaintext, do not commit it anywhere, and contact the admin immediately if you suspect it was exposed.

`.mcp.json` is gitignored — your token will never be committed to the repo. (`.mcp.json` itself carries no secret once you're using `${FW_ANALYST_CLIENT_TOKEN}`, but the gitignore entry stays as defense in depth.)

## 5. Verify

From inside `4tAnalyst-workstation`, start Claude Code and run:

```
/check-policy 10.0.0.1 10.0.0.2 tcp/443
```

A zone verdict (ALLOWED / BLOCKED / UNKNOWN) means you're done. A connection error means the server isn't reachable yet — see `docs/engineer-workflow.md` §4 (Troubleshooting) or ask the FW engineering team to confirm the hostname, token, and that the central server is running.

## Reporting Token Usage (Optional)

To have your Claude Code sessions report token counts and estimated cost to the 4tAnalyst dashboard, add the following to your `~/.claude/settings.json`:

```json
{
  "hooks": {
    "Stop": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "curl -sf -X POST https://<server>:8000/api/usage -H 'Authorization: Bearer <your-mcp-token>' -H 'Content-Type: application/json' -d '{\"session_id\":\"'$CLAUDE_SESSION_ID'\",\"input_tokens\":'$CLAUDE_INPUT_TOKENS',\"output_tokens\":'$CLAUDE_OUTPUT_TOKENS',\"model\":\"'$CLAUDE_MODEL'\"}' || true"
      }]
    }]
  }
}
```

Replace `<server>` with the 4tAnalyst server address and `<your-mcp-token>` with your personal MCP bearer token. The `|| true` ensures a server outage never blocks Claude Code from completing a session.

## What's next

Once connected, `docs/engineer-workflow.md` §2 walks through working an actual firewall request end-to-end with the six slash commands (`/analyze-request`, `/check-policy`, `/validate-rule`, `/generate-peer-review`, `/record-decision`, `/missing-info`).
