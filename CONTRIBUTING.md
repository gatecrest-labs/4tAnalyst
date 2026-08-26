# Contributing

## Who maintains what

| Component | How to update | Who owns it |
|---|---|---|
| Zone definitions and subnets | 4THealth admin UI | Network / OT team |
| Zone policy rules | 4THealth admin UI | Security team |
| `standards_mcp/naming.yaml` | Edit the file, commit, restart standards_mcp | FW engineering team |
| `standards_mcp/review_requirements.yaml` | Edit the file, commit, restart standards_mcp | FW engineering team |
| MCP server code | Pull request, see below | 4tAnalyst maintainers |
| `fgplanner` (deterministic engine) | Lives in the separate [`fortigate-change-planner`](https://github.com/Alski-MPLS/fortigate-change-planner) repo — pull request there; changes alter what engineers implement, tests required | fortigate-change-planner maintainers |
| `.claude/skills/<name>/SKILL.md` | Pull request or direct edit | FW engineering team |

## Updating naming conventions or review requirements

Edit `standards_mcp/naming.yaml` or `standards_mcp/review_requirements.yaml` directly. Changes take effect on the next MCP server restart — no code changes needed.

After editing:
1. Commit the change to the repo
2. Pull the change on the central server (`git pull`)
3. Restart the `standards_mcp` server process

## Adding a new MCP server

Each MCP server is an independent Python package under its own directory. To add a new one:

1. Create a new directory: `<name>_mcp/`
2. Add `__init__.py`, `server.py`, `pyproject.toml` following the pattern in `fortimanager_mcp/`
3. If the server needs credentials, add a section to `credentials.yaml.example` and document it in `docs/configuration.md`
4. Install it: `uv pip install -e <name>_mcp/`
5. Add it to the server start script and eventually `docker-compose.yml`
6. Add a smoke test entry to `docs/installation.md`

## Pull request guidelines

- Keep pull requests focused — one logical change per PR
- MCP server changes should include a manual smoke test result in the PR description
- Do not commit `credentials.yaml`, `policy_db.json`, or any file containing internal IPs, hostnames, or API keys
- Update `docs/` if the change affects installation, configuration, or usage

## Testing and CI gates

Before opening a PR, run the unit test suite from the repo root:

```bash
uv run pytest -q tests/
```

`tests/` covers this repo's own packages (matching, auth, ADOM guard, rate
limiting, clients). The deterministic planner's own tests live in the
separate [`fortigate-change-planner`](https://github.com/Alski-MPLS/fortigate-change-planner)
repo and run there.

CI (`.github/workflows/smoke-tests.yml`) runs on every push and PR to `main`
and must pass before merge:

- **`unit-tests`** — `pytest -q tests/` with all packages installed, plus
  `pip-audit --skip-editable` against the resolved dependency set
- **`gitleaks`** — scans the diff for committed secrets (API keys, tokens,
  credentials); if it flags a false positive, fix the pattern rather than
  suppressing the check
- **`smoke-tests`** — containerised, auth-aware checks (`scripts/run_smoke.py`)
  against the unified server built from `docker-compose.ci.yml`
- **`sensitive-string-check`** (`.github/workflows/sensitive-string-check.yml`)
  — this repo is public; blocks any push/PR that reintroduces the redacted
  former employer's name/domain (see `scripts/check-sensitive-strings.sh` —
  the target strings are stored base64-encoded there, and any match is
  redacted from the check's own output, so nothing plaintext ever appears in
  a commit, a PR diff, or a CI log)

A PR that fails any of these gates will not be merged. If you add a new MCP
server or dependency, run `pip-audit` locally first so vulnerable pins are
caught before CI does.

Run `git config core.hooksPath .githooks` once after cloning to enable the
local pre-commit hook, which runs the same check before every commit
(bypass with `git commit --no-verify` if it's a false positive).

## Running servers locally for development

```bash
# per-package stdio mode — easiest for debugging; server logs appear in the terminal
uv run python -m zone_mcp.server

# unified server, http mode — matches production behaviour
MCP_TRANSPORT=http FASTMCP_PORT=8000 FW_ANALYST_TOKEN=<token> \
    uv run python -m fwanalyst_server

# deterministic planner, exercised via the wired plan_change MCP tool above —
# fgplanner (the external package) ships its own standalone CLI too
# (`python -m fgplanner ...`), but it ships no default clients and reads no
# credentials.yaml by design (see fgplanner/clients.py); running it directly
# from within this repo without registering your own client factories first
# fails with "no FortiManager client configured".
```

Each per-package MCP server still runs independently over stdio for development. Production serves a single aggregated endpoint (fwanalyst_server, port 8000) — when you add a tool, register it in fwanalyst_server/server.py and bump the expected count in tests/test_fwanalyst_auth.py.

Local helper scripts are available in `scripts/`:

- `scripts/start-all.sh` — start the unified server in the background (activates .venv if present)
- `scripts/smoke-test.sh` — quick curl-based auth check against port 8000
- `scripts/run_smoke.py` — pure-Python smoke tester (no extra packages)

See `docs/installation.md` for usage and the `docker-compose.example.yml` and `systemd/` templates for example deployment approaches.
