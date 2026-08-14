# Architecture

## Problem this solves

Firewall engineers spend significant time on the research and documentation phases of rule request processing: parsing incoming requests, identifying which firewalls are in path, looking up existing rules, checking segmentation policy, validating naming and logging standards, and assembling peer review documentation. 4tAnalyst automates that layer, leaving engineers to make the actual judgment calls.

---

## How it works

The core architectural rule is **"the LLM orchestrates, code computes."** Everything correctness-critical — does an existing rule cover the request, which objects to reuse, where a new rule must be inserted, the exact FortiGate CLI — is computed by the deterministic planning core, published separately as [`fortigate-change-planner`](https://github.com/Alski-MPLS/fortigate-change-planner) (importable module `fgplanner`, pure Python, pytest-covered, no LLM anywhere in the decision path) and installed as a dependency of `fwanalyst_server`. Claude Code is the conversational front end: it collects the request, calls the planner's `plan_change` MCP tool, and presents the result verbatim.

Engineers interact through [Claude Code](https://claude.ai/code) on their laptops using slash commands (e.g., `/analyze-request`, `/check-policy`). Claude Code connects to the central unified MCP server (`fwanalyst_server`) over streamable-HTTP with a bearer token. The central server holds all firewall API credentials and makes read-only queries to FortiManager and the 4THealth zone policy system on the engineer's behalf. The planner is also runnable directly with no LLM at all, via `fgplanner`'s own standalone CLI (`python -m fgplanner --src ... --dst ... --service ... --firewall DEVICE:ADOM`) — the same engine, a plain CLI, which matters in a regulated environment where the AI inference path may be approved later than the tool itself. Note that `fgplanner` ships no default FortiManager/zone-policy clients — `fwanalyst_server/server.py` registers factories built from `credentials.yaml` before every `plan_change` call, so within this repo the wired no-LLM path is the `plan_change` MCP tool, not an unwired `python -m fgplanner` invocation.

The system targets Fortinet (FortiManager/FortiGate) exclusively. A NetBrain integration is planned for a future phase to provide automated network topology once API details are confirmed.

```
Engineer Laptop                           Engineer terminal (no LLM path)
  Claude Code                               python -m fgplanner
      │                                         │
      │ MCP streamable-HTTP + bearer token      │
      ▼ (port 8000, path /mcp)                  │
fwanalyst_server (single process) ──────────────┤
  │                                             │
  ├── PathDispatcher (port 8000)
  │     ├── /admin, /api  ──▶  Admin Web UI (FastAPI)
  │     │                        ├── Dashboard (psutil metrics)
  │     │                        ├── Usage Graph (analytics.db)
  │     │                        └── ADOM / User Management
  │     └── /mcp  ──▶  MCP middleware stack
  │                      ├── plan_change ──▶ fgplanner  ◀──────────────┘
  │                      │                    ├──▶ 4THealth external API
  │                      │                    ├──▶ FortiManager JSON-RPC
  │                      │                    └──▶ standards YAML + render_report
  │                      ├── standards tools  ──▶ local files
  │                      ├── fortimanager tools ──▶ FortiManager API
  │                      └── feedback tools   ──▶ SQLite
  │
  └── analytics.db (tool calls, token usage, system metrics)
```

### Web admin layer

The `PathDispatcher` middleware inspects the URL path on every incoming request before the bearer auth stack is evaluated. Requests to `/admin/*` and `/api/*` are routed to the FastAPI admin app (session-cookie auth, local accounts). Everything else reaches the existing MCP bearer-auth stack unchanged. The two auth models never interact.

`UsageMiddleware` sits inside the bearer-auth stack and logs every `tools/call` invocation to `analytics.db` automatically — zero client configuration needed. Engineers can optionally enrich these records with actual token counts by adding a one-line Claude Code `Stop` hook (see `docs/workstation-onboarding.md`).

**Firewall credentials live only on the central server.** Engineers never need direct API access to FortiManager. The per-domain packages still exist as code in this repo (and run individually over stdio for development), but production serves one authenticated endpoint instead of several unauthenticated SSE ports.

### fgplanner — the deterministic core (external package)

`plan_change(src, dst, service, firewalls, justification, ticket_id, src_group, dst_group)`, from the [`fortigate-change-planner`](https://github.com/Alski-MPLS/fortigate-change-planner) package, performs, in tested code. `src`/`dst`/`service` each accept a single value, a comma-separated string, or a list — one call plans **one consolidated policy per firewall** covering every combination:

1. **Zone verdict** — live 4THealth query per src×dst×service combination (`fgplanner/fetch.py`); API failure raises a typed `PlannerDataError`, never silently treated as "no result". IPs 4THealth cannot resolve default to the catch-all **Internet** zone (with an explanatory note) and the verdict is re-derived from the live policy table — the Internet zone is always critical risk with the internet-inbound/outbound logging profile. Any UNKNOWN combination makes the whole request UNKNOWN (no CLI); mixed ALLOWED+BLOCKED verdicts raise an error telling the engineer to split the request — a single rule must never carry both.
2. **Existing-rule coverage** — fetches every policy package installed on each named device and evaluates them with set semantics (`fortimanager_mcp/matching.py`): service objects resolved to numeric proto/port ranges (so "80" can never match `TCP_8080`), address groups recursed with cycle guards, negate flags / schedules / disabled status honoured, and coverage judged only against rules scoped to the flow's actual interface pair (a broad LAN→WAN rule never "covers" an east-west flow). "Already covered" requires **every** src×dst pair fully covered (possibly by different rules); partial coverage surfaces an overlap warning. Package fetch failures mark the snapshot **degraded** — a degraded device is never reported as "already covered", and "no rule found" is flagged as inconclusive.
3. **Object reuse & grouping** — exact-match search of existing address/service objects (per-ADOM shadows global); creates `H_*` / `N_*` / `SVC_*` objects per naming.yaml only when nothing reusable exists. Sides with more than 3 members automatically get a dedicated address group (`GRP_<ticket>_SRC/DST`); an explicit `src_group`/`dst_group` name forces grouping at any size.
4. **Insertion point** (`fgplanner/insertion.py`) — first-match shadowing analysis over the package's ordered policies: the new rule is placed before the first enabled policy that would otherwise match any of the traffic; fully-shadowing earlier rules (all pairs) and later rules the new one would fully shadow are reported. Placement is a recommendation with a rationale the engineer confirms.
5. **Group-append alternative (Option B)** — when a near-miss enabled rule would cover the flow if the missing endpoint(s) were appended to an address group it references, the plan carries that smaller change as an alternative — always with the ADOM-wide blast radius (every other policy referencing the group, directly or through group nesting), and never for negated sides (appending to a negated side removes access). The engineer chooses Option A (new policy) or Option B, never both.
6. **Standards** (`fgplanner/standards.py`) — risk level (unknown zones fail safe to critical), logging profile, approval chain — the decision rules previously encoded as prose in SKILL.md, now unit-tested code.
7. **Output** — the exact `scripts/render_report.py` payload (HTML report + `implementation.conf`), plus fixed-template recommendation text.

The LLM never sees intermediate data and is instructed to relay the payload verbatim. Two runs on the same inputs produce the same plan — auditable behaviour for a regulated environment.

---

## MCP servers

In production a single process (`fwanalyst_server`, port 8000) aggregates every tool below plus `plan_change` behind streamable-HTTP with static-bearer authentication (fail-closed: it refuses to start in HTTP mode without a token). Requests that pass auth are also subject to a per-session call budget (`fwanalyst_server/rate_limit.py`, default 300 requests/60s per `Mcp-Session-Id`, `429` past that) so a runaway session can't hammer FortiManager — see `docs/configuration.md` for the env vars. The per-domain packages remain independently runnable over stdio for local development.

### standards_mcp

Zone segmentation policy, naming conventions, and review requirements.

Tools: `get_zone_matrix`, `check_traffic`, `get_naming_convention`, `get_required_log_settings`, `get_review_requirements`

Data is loaded from `naming.yaml` and `review_requirements.yaml` at startup (team-maintained config files). Zone/policy data was previously loaded from a local `policy_db.json` — this is being migrated to live 4THealth API queries via `zone_mcp`. `naming.yaml` contains FortiGate conventions only.

### fortimanager_mcp

Read-only queries to FortiManager (7.4/7.6, JSON-RPC over HTTPS).

Tools: `get_adoms`, `get_devices`, `search_policies`, `get_address_object`, `search_address_objects`, `get_service_object`, `get_policy`, `get_interface_map`, `get_routing_table`

`search_policies` uses the set-semantics matching layer (`matching.py`) and returns a structured result with `degraded`/`packages_failed` so an empty match list can never be silently misread as "no rule exists".

Authentication: REST API Administrator key sent as a Bearer header (stateless). Supports multi-host failover.

### feedback_mcp

Stores engineer decisions (approved/rejected/deferred) and builds an audit trail.

Tools: `record_feedback`, `get_similar_cases`, `get_feedback_summary`

Storage: SQLite in Phase 1–3, PostgreSQL in Phase 5.

### intake_mcp

Parses the standard firewall request spreadsheet (.xlsx) and accepts manual conversational entry. Normalizes both into the same `FirewallRequest` structure.

Tools: `parse_spreadsheet_file`, `parse_manual_entry_tool`, `describe_template`

Spreadsheet tabs supported: FW Rules, Group Request, IP Block/Allow, VPN.

### zone_mcp

IP-to-zone resolution and traffic policy verdicts via the 4THealth external API.

Tools: `query_zone_policy`, `get_zones`, `get_policies`, `find_zone_for_ip`, `check_ip_traffic`

This is the IP → Firewall Mapper for Phase 2. Given a source and destination IP, it resolves both to zones and returns the governing policy verdict. The 4THealth application is the source of truth for zone definitions and subnets.

### netbrain_mcp — planned

Network topology queries via the NetBrain API. This MCP server is not yet built — the NetBrain API integration details are TBD. When available, it will provide automated path discovery: given a source and destination IP, return the firewalls that sit in the traffic path.

Until `netbrain_mcp` is available, engineers declare affected firewalls explicitly (see below).

---

## Firewall topology

4tAnalyst does not currently auto-discover which firewalls sit in the traffic path between two IPs.

The current approach: the submitting engineer declares the firewalls explicitly. 4tAnalyst then queries those specific devices. This is a deliberate tradeoff — explicit is more reliable than guessed, and engineers generally know which devices are in path for their environment.

**NetBrain integration (planned):** NetBrain has a network topology API that can return the device path for a given source/destination flow. When the API details are confirmed, `netbrain_mcp` will be built to expose this capability. At that point, automatic path suggestion will be added to the `/analyze-request` workflow — framed as a hint the engineer confirms, not an authoritative determination.

---

## Data flow for a typical request

```
Engineer: /analyze-request
                │
                ▼
    Claude collects src IP(s), dst IP(s), service(s),
    business justification, firewalls (DEVICE:ADOM), ticket
                │
                ▼
        plan_change (ONE tool call for the whole request)
                │
        fgplanner/engine.py  (deterministic, external package)
          ├─ 4THealth verdict + zone domains
          ├─ per-device snapshot (packages, policies, objects, interfaces)
          ├─ coverage / object reuse / insertion analysis
          ├─ naming, logging, risk, approval chain
          └─ FortiGate CLI + render_report payload
                │
                ▼
    Claude presents the payload verbatim
    → scripts/render_report.py → report.html + implementation.conf
```

---

## Phase roadmap

| Phase | Scope | Status |
|---|---|---|
| 1 | Standards MCP — zone matrix, naming, review requirements | Complete |
| 2 | FortiManager MCP, IP-to-zone mapper (zone_mcp) | Complete |
| 3 | Recommendation engine with reasoning chain and risk scoring; NetBrain topology integration (pending API details) | Planned |
| 4 | Peer review package generation, feedback loop, change record scaffolding | Planned |
| 5 | mTLS hardening, Ansible change preview, Postgres migration, HA | Planned |

---

## Design decisions

| Decision | Rationale |
|---|---|
| LLM orchestrates, code computes | Correctness-critical logic (coverage, reuse, insertion, CLI) lives in tested Python, not prompt prose — deterministic, auditable, regression-tested |
| Planner runs without an LLM (`python -m fgplanner`) | Compliance can approve the deterministic tool independently of the AI inference path; also the correct correctness posture |
| One authenticated endpoint instead of five SSE ports | One TLS termination, one token check, one health check; unauthenticated multi-port SSE was a compliance finding waiting to happen |
| Typed degradation (`degraded`, `PlannerDataError`) | An FMG timeout must never be read as "no existing rule" — that silently produces duplicate/shadowed rules |
| Unresolved IPs default to the Internet catch-all zone | Enumerating all internet space as subnets is not viable; an unmatched IP is by definition "not any named zone" — treated as Internet with critical risk, never silently UNKNOWN |
| Mixed verdicts refuse to consolidate | If some combinations are ALLOWED and others BLOCKED, one rule cannot honour both — the planner errors with "split the request" instead of guessing |
| Group-append offered only with full blast radius | Editing a shared address group changes every rule that references it; the alternative is never presented without that list, and never for negated sides |
| Central server holds all credentials | Keeps API keys off engineer laptops; single point of revocation |
| Read-only MCP tools throughout | No accidental changes; Claude recommends, engineers execute |
| Engineer declares firewalls explicitly | Reliable over guessed; NetBrain topology integration planned for future phase |
| 4THealth as zone/policy source of truth | 4THealth has a built-in admin UI and API; eliminates manual CSV exports from TUFIN |
| Fortinet only (FortiManager) | This deployment's environment uses FortiGate/FortiManager |
| Feedback store from day one | Decision data is valuable for Phase 3 recommendations; start collecting early |
| SQLite first, Postgres later | SQLite is zero-ops for a small team; migrate when concurrency or retention needs grow |
