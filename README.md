<img alt="4tAnalyst logo" src="docs/assets/logo.svg" width="240">

# 4tAnalyst

An AI assistant for firewall change request analysis. Engineers interact with it through [Claude Code](https://claude.ai/code) using slash commands — 4tAnalyst handles policy research, standards validation, and peer review package generation, keeping the engineer as the final decision-maker.

> Note: This is an independent open-source project and is not affiliated with, endorsed by, or supported by Fortinet, Inc. FortiManager is a trademark of Fortinet, Inc.

> Note: This a work in progress. It will change as I continue to build it out. Any recommendations are encouraged. 

## What it does

Firewall engineers typically spend significant time on rule request processing: parsing incoming requests, identifying which firewalls are affected, researching existing rules, checking against segmentation policy, validating naming and logging standards, and assembling peer review documentation. 4tAnalyst automates that research layer, reducing it to judgment calls.

Given source IP(s), destination IP(s), and service(s) — a single value or a list of each — 4tAnalyst will:

- Resolve IPs to network zones and return a policy verdict (ALLOWED / BLOCKED / UNKNOWN) for every source×destination×service combination; IPs that don't resolve to any zone default to the catch-all **Internet** zone (critical risk) rather than silently failing
- Plan **one consolidated policy per firewall** covering all combinations, refusing to consolidate when policy gives mixed verdicts (some combinations allowed, some blocked — the request must be split)
- Search named firewalls for existing rules that match or overlap the request (set-semantics matching — service objects resolved to numeric port ranges, address groups recursed, coverage judged only against rules scoped to the flow's actual interfaces)
- Decide which address/service objects can be reused and which must be created, auto-creating an address group when a side has more than 3 members (or a named group on request)
- Compute where a new rule must be inserted in the policy package (first-match shadowing analysis)
- Offer a smaller **Option B** when a near-miss rule exists: append the missing endpoint(s) to an address group that rule already references — always accompanied by the full blast radius (every other rule that group change would affect)
- Validate proposed object names and logging settings against your standards
- Determine the required approval chain based on zone risk classification
- Generate a complete peer review package for the second-engineer sign-off
- Write an HTML report and a ready-to-use FortiGate CLI config (or exception-request language, if blocked) that engineers attach directly to the change ticket

All of that analysis runs in the **deterministic change planner** (`planner/`)
— tested Python code, no LLM in the decision path. Claude Code is the
conversational front end: it collects the request, calls the planner's
`plan_change` tool, and presents the result. The same engine runs standalone:

```
python -m planner --src "10.1.2.3, 10.1.2.4" --dst 10.9.8.7 \
    --service "tcp/8443, tcp/22" --firewall MNHQ-FW01:OT-ADOM \
    --ticket CHG0012345 [--src-group GRP_VENDOR_X]
```

**What it does not do:** push changes to firewalls, bypass peer review, or make decisions. All operations are read-only against the management APIs.

**Important limitations:**
- Does not automatically discover which firewalls sit in the traffic path. The submitting engineer must identify and name the affected devices. Automated path suggestion is a planned future feature.
- All verdicts and recommendations are advisory. Engineers are accountable for every decision — the tool accelerates research, it does not replace judgment.
- Zone policy verdicts reflect *intended segmentation policy*, not the actual current state of firewall rules. ALLOWED does not mean a rule exists on the firewall.

## Web Admin Interface

A browser-based admin panel at `http://<server>:8000/admin` provides:

- **Dashboard** — real-time CPU, memory, and disk metrics with time-series charts (1h–7d)
- **Graph** — AI token usage and estimated cost per engineer over configurable time ranges
- **Admin tab** — manage engineer MCP tokens and their ADOM access restrictions; manage local user accounts

Authentication uses local accounts (RADIUS/LDAP upgrade path built in). Create the first admin user with:
```bash
python -m fwanalyst_server.admin create-user <username> --role admin
```

## Architecture

```
Engineer Laptop (Claude Code)          Engineer terminal (no LLM)
        │                                      │
        │  MCP streamable-HTTP                 │  python -m planner
        │  (bearer token, port 8000)           │
        ▼                                      ▼
Central server: fwanalyst_server ──▶  planner/  (deterministic core)
  one endpoint aggregating:                 │
  ├── plan_change  ◀── THE tool             ├─▶ 4THealth zone API (verdicts)
  ├── standards tools (naming/approvals)    ├─▶ FortiManager JSON-RPC (7.4/7.6)
  ├── fortimanager read-only tools          └─▶ render_report (HTML + .conf)
  ├── feedback/audit tools
  ├── intake tools (.xlsx parsing)
  └── zone tools (live 4THealth lookups)
```

Design rule: **the LLM orchestrates, code computes.** Everything that must be
right — rule coverage, object reuse, insertion point, CLI — is computed by
`planner/` and covered by unit tests. Firewall credentials live only on the
central server; engineers authenticate to it with a bearer token (per-engineer
identity planned for Phase 4). Engineers never need direct API access.

## Quick start

1. Clone this repo on the central MCP server
2. Copy `credentials.yaml.example` to `credentials.yaml` and fill in API credentials
3. Install all packages and start the servers — see [Installation](docs/installation.md)
4. On each engineer laptop, point Claude Code at the central server — see [Configuration](docs/configuration.md)
5. Open any directory in Claude Code and type `/analyze-request`

Running tests and CI

- Unit tests: `pytest -q tests/` (planner, matching, insertion, engine, auth, and client tests — no live systems needed)
- Smoke tests: `uv run python scripts/run_smoke.py` or `./scripts/smoke-test.sh` (asserts auth is enforced on port 8000)
- CI: GitHub Actions runs `build-dev-image`, `unit-tests`, and `smoke-tests` on pushes and PRs to `main`.

## Documentation

| Doc | Contents |
|---|---|
| [Installation](docs/installation.md) | Server and workstation setup, step by step |
| [Configuration](docs/configuration.md) | `credentials.yaml` reference, environment variables |
| [Usage](docs/usage.md) | Slash commands with real examples |
| [Engineer Workflow](docs/engineer-workflow.md) | Step-by-step guide: setup, working requests, data flow, troubleshooting |
| [Workstation Onboarding](docs/workstation-onboarding.md) | One-page laptop setup for the sparse-checkout workflow |
| [Compliance](docs/compliance.md) | Data-sensitivity/compliance considerations for regulated deployments (NERC CIP, HIPAA, PCI-DSS, SOX, GDPR — regime-agnostic), inference path comparison, questions for compliance team |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and fixes |
| [Architecture](docs/architecture.md) | Design decisions, data flow, phase roadmap |

## Prerequisites

- Central Linux server (Ubuntu 22.04+) with network access to FortiManager management IP(s)
- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- Claude Code installed on each engineer workstation — requires an Anthropic subscription (Claude Max or API access) per user; confirm licensing and IT/InfoSec approval before deployment
- Read-only API credentials for FortiManager
- Access to a 4THealth instance with the external zone policy API enabled

## Security

See [SECURITY.md](SECURITY.md) for credential handling, network access requirements, and vulnerability reporting.

## License

No license has been chosen yet for public distribution. All rights reserved until a license is added.
