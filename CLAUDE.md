# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

4tAnalyst is a Python-based AI assistant that automates firewall rule request analysis for an energy utility. It exposes MCP (Model Context Protocol) servers so Claude Code can validate firewall requests against company network segmentation policy, naming conventions, and approval workflows — eliminating the need for engineers to manually check policy matrices and routing requests.

## Commands

```bash
# Install all packages (run from repo root)
uv pip install -e mcp_common/ -e standards_mcp/ -e fortimanager_mcp/ -e feedback_mcp/ \
    -e intake_mcp/ -e zone_mcp/ -e planner/ -e fwanalyst_server/

# Run the deterministic planner directly (no LLM, no server needed)
uv run python -m planner --src 10.1.2.3 --dst 10.9.8.7 --service tcp/8443 \
    --firewall MNHQ-FW01:OT-ADOM --ticket CHG0012345 [--json-only]

# Unified server, stdio mode (development / debug)
uv run python -m fwanalyst_server

# Unified server, production (streamable-HTTP + bearer auth on one port).
# Refuses to start in HTTP mode without a token (FW_ANALYST_TOKEN env or
# credentials.yaml server.auth_token; env wins).
MCP_TRANSPORT=http FASTMCP_HOST=0.0.0.0 FASTMCP_PORT=8000 \
    FW_ANALYST_TOKEN=<token> uv run python -m fwanalyst_server

# Individual per-package servers still run over stdio for debugging
uv run python -m zone_mcp.server   # etc.

# Docker (single fwanalyst service on port 8000)
docker compose up            # uses docker-compose.yml (mounts repo for live edits)
docker compose -f docker-compose.ci.yml up  # CI image — no mounts

# Unit tests
pytest -q tests/             # runs all tests (no live systems needed)
pytest -q tests/test_engine.py tests/test_insertion.py  # just the planner

# Rebuild policy_db.json after TUFIN CSV exports change
uv run python standards_mcp/build_policy_db.py

# Smoke check (server must be running; asserts 401 without token, 200 with)
uv run python scripts/run_smoke.py
```

## Architecture

**Core design rule: the LLM orchestrates, code computes.** All correctness-critical analysis (rule coverage, object reuse, insertion point, CLI generation) lives in the deterministic `planner/` package. In production, one process (`fwanalyst_server`, port 8000, streamable-HTTP + bearer auth) aggregates every tool including `plan_change`. The per-domain packages below remain individually runnable over stdio for development.

`netbrain_mcp` is planned but not yet started. `servicenow_mcp` is not planned — ServiceNow has no available read-only API; intake is handled by `intake_mcp`. The system targets Fortinet (FortiManager) exclusively.

### Package overview

| Package | Status | Description |
|---|---|---|
| `planner` | **Complete** | **Deterministic change planner** — the product core. `plan_change()` computes verdict, coverage, reuse, insertion, CLI. Also a standalone CLI (`python -m planner`) |
| `fwanalyst_server` | **Complete** | Unified MCP server (port 8000, streamable-HTTP, static-bearer auth, fail-closed) aggregating all tools + `plan_change` |
| `standards_mcp` | **Complete** | Zone matrix, naming.yaml, review_requirements.yaml, static policy evaluation |
| `fortimanager_mcp` | **Complete** | Read-only FortiManager JSON-RPC queries (7.4/7.6) + `matching.py` set-semantics layer |
| `feedback_mcp` | **Complete** | SQLite decision/audit store with similarity lookup |
| `intake_mcp` | **Complete** | .xlsx parser + manual entry normaliser |
| `zone_mcp` | **Complete** | Live 4THealth zone policy API (IP→zone + verdict) |
| `mcp_common` | **Complete** | Shared input validation, sanitized errors, and log masking used by fortimanager_mcp |
| `netbrain_mcp` | **Planned** | Automated path discovery — blocked on NetBrain API access |

### planner/ (deterministic core)

- **`engine.py`** — `plan_change(src, dst, service, firewalls, justification, ticket_id, src_group="", dst_group="", fmg_client=None, zone_client=None)` → `ChangePlan`; `to_report_payload(plan)` emits the exact `render_report.py` schema. **Consolidated multi-value requests**: `src`/`dst`/`service` each accept a single value, a comma-separated string, or a list — call the planner ONCE per request; it emits ONE policy per firewall covering every combination. Zone verdicts are computed per src×dst×service combination: any UNKNOWN → `unknown_no_action`; mixed ALLOWED+BLOCKED → `PlannerDataError("request", …split the request…)`. Sides with more than 3 members (`GROUP_THRESHOLD`), or with an explicit `src_group`/`dst_group` name, get a dedicated address group (default `GRP_<ticket>_SRC/DST`). "Already covered" requires EVERY src×dst pair fully covered (possibly by different rules); partial coverage adds an overlap warning. When a near-miss rule would cover the flow if the missing endpoint(s) were appended to a group it references, the plan carries a `GroupAppendAlternative` (Option B, `members` list) with an ADOM-wide blast-radius list of every other rule referencing that group (directly or via nesting); never offered for negated sides. Decision table: UNKNOWN verdict → `unknown_no_action`; BLOCKED → `blocked_exception`; ALLOWED + every device fully covered (enabled, unconditional, non-degraded) → `already_covered`; else `new_rule`.
- **`fetch.py`** — `DeviceSnapshot` (packages, ordered policies, catalogs, interfaces), `fetch_zone_verdict`, `resolve_interfaces`/`resolve_interface`. Failures raise typed `PlannerDataError(source, detail)`; per-package failures set `degraded` — a degraded device is never claimed "already covered". IPs 4THealth cannot resolve default to the catch-all **Internet** zone (with a note) and the verdict is re-derived from the live policy table; any flow touching the Internet zone is critical risk with the `allow_internet_inbound`/`allow_internet_outbound` logging profile.
- **`insertion.py`** — `plan_insertion(...)` first-match shadowing analysis → insert-before policy ID + rationale + `shadowed_by`/`would_shadow`.
- **`standards.py`** — risk level (unknown zone fails safe to critical), `rule_type_for` logging profile mapping, naming/policy-name generation, review requirements. `permissiveness_warnings()` runs a least-privilege review of the request itself (any-source/any-destination, CIDRs wider than /16, ANY service, port ranges spanning >1024 ports; any/any/any gets an explicit reject-or-rescope warning) — warnings only, surfaced on every plan. A wildcard service request reuses FortiGate's built-in `ALL` object instead of generating a service-object CLI.
- **`cli_gen.py`** — exact FortiGate CLI blocks; `<TICKET_ID>` placeholders substituted by render_report.
- **`__main__.py`** — standalone CLI; exit 2 on data-source failure.

### fwanalyst_server/

- **`server.py`** — single FastMCP aggregating all 31 per-package tools (via `add_tool`) + `plan_change` (32 total; `tests/test_fwanalyst_auth.py` asserts the count — update it when adding tools).
- **`context.py`** — Thin shared module: exports `allowed_adoms_var: ContextVar[set[str]]`. Lives here (not in `auth.py`) so `fortimanager_mcp` can import it without a circular dependency.
- **`auth.py`** — `require_bearer(app, token, creds=None)` ASGI wrapper; constant-time compare; fail-closed (`AuthConfigError` on empty token). When `creds` is provided, resolves the bearer token to an allowed ADOM set via `_resolve_allowed_adoms()` and injects it into `allowed_adoms_var` for the duration of each request. Named per-engineer tokens from `server.tokens` are accepted in addition to the primary admin token.
- **`rate_limit.py`** — `rate_limit(app, max_requests, window_seconds)` ASGI wrapper; per-`Mcp-Session-Id` sliding-window call budget, `429` past the limit (defaults 300 req/60s, `FW_ANALYST_RATE_LIMIT_MAX`/`FW_ANALYST_RATE_LIMIT_WINDOW_SECONDS`, `MAX=0` disables). Applied inside `require_bearer` in `__main__.py` so unauthenticated requests never consume budget.
- **`__main__.py`** — `MCP_TRANSPORT=stdio` (default) or `http` (uvicorn + streamable_http_app, path `/mcp`). In HTTP mode also sets `transport_security` (DNS-rebinding protection, `FW_ANALYST_ALLOWED_HOSTS` or `credentials.yaml` `server.allowed_hosts`) — unset keeps the MCP SDK's localhost-only default, which rejects real engineer traffic once deployed to a real hostname. Loads full `credentials.yaml` and passes it to `require_bearer` so per-engineer ADOM restrictions are enforced.

### Critical data-source warning

`standards_mcp.check_traffic` uses **static** TUFIN-era data (`policy_db.json`). `zone_mcp.check_ip_traffic` queries the **live** 4THealth API. These can return different verdicts for the same flow. **Always use `zone_mcp` for policy verdicts in engineer workflows.** Use `standards_mcp` only for naming conventions, logging rules, and approval chain lookups.

### standards_mcp/

**`server.py`** — FastMCP server exposing 5 tools. Loads `policy_db.json`, `naming.yaml`, and `review_requirements.yaml` at startup (cached). Tools:
- `get_zone_matrix()` — full zone-pair policy table (static)
- `check_traffic(src_zone, dst_zone, service)` — ALLOWED / BLOCKED / UNKNOWN (static data — do not use for verdicts)
- `get_naming_convention(object_type, platform)` — FortiGate naming patterns
- `get_required_log_settings(rule_type)` — logging requirements per rule category
- `get_review_requirements(risk_level)` — approval chain, SLA, and change window

**`policy_engine.py`** — stateless evaluation logic (no I/O). Key functions:
- `zones_for_endpoint(ip_or_cidr, zones)` — resolves IP to zone(s) using most-specific subnet match
- `ancestor_zones(zone_name, zones)` — BFS traversal of zone hierarchy
- `find_matching_policies(src_zones, dst_zones, zones, policies)` — finds all rules covering a zone pair (including parent zones)
- `evaluate(policies, services)` — returns verdict with precedence: `block-all` > `block-only` + service match > `allow-all`

**`build_policy_db.py`** — one-shot ingestion script. Parses `policy-data/zones.csv` and TUFIN USP policy CSVs into `policy_db.json`. Never edit `policy_db.json` by hand.

### fortimanager_mcp/

**`client.py`** — JSON-RPC client authenticated via a REST API Administrator's API key, sent as an `Authorization: Bearer` header on every call (`session: null` — this admin type has no session login, so there's nothing to keep alive or re-authenticate). Also handles primary/secondary host failover and range-based pagination. Uses `httpx`.

**`matching.py`** — set-semantics matching layer: `PortRange`, `parse_service_request` ("443", "tcp/8443", "ssh", "any"), `ServiceCatalog`/`AddressCatalog` (resolve FMG object/group refs to numeric ranges/networks; group recursion with cycle guards; unknown refs → `None`, never a silent non-match), `PolicyMatcher.evaluate()` → `MatchResult(matched, full_cover, disabled, conditional_schedule, unknown_refs)`. This is what makes "80" unable to match `TCP_8080`.

**`query.py`** — high-level query helpers consumed by `server.py`. `search_policies` returns a structured dict `{policies, packages_searched, packages_failed, degraded}` — when `degraded` is True an empty match list must NOT be read as "no rule exists".

**`server.py`** — FastMCP exposing 17 read-only tools. All tools that accept an `adom` parameter call `_require_adom(adom)` as their first line — hard-erroring if the caller's token is not allowed for that ADOM. `get_adoms()` silently filters the returned list to the caller's allowed set. In stdio/dev mode (no HTTP middleware, `allowed_adoms_var` unset) all tools default to full access.
- `get_system_status`, `get_ha_status` — FortiManager version/hostname/serial and HA cluster status (no ADOM param — not guarded)
- `get_adoms`, `get_devices`, `search_devices` — discovery (search_devices filters get_devices client-side by name/platform/OS/connection status)
- `search_policies(adom, device, src_ip, dst_ip, service)` — structured set-semantics policy search
- `get_address_object`, `search_address_objects(adom, ip)` — find existing objects before creating new ones
- `get_service_object` — service lookup
- `get_policy(adom, pkg, policy_id)` — full policy detail
- `get_interface_map(adom, device)` — interface-to-zone assignments
- `get_routing_table(adom, device)` — static routes for path analysis
- `list_device_vdoms(adom, device)` — VDOMs configured on a device
- `get_device_interface_config(adom, device, vdom)` — Device-DB interface config with VLAN filtering
- `get_device_client_location(adom, device, ip, mac, hostname)` — locate a client on detected-client inventory
- `get_device_sdwan(adom, device, vdom)` — Device-DB SD-WAN config (zones, members, health-checks)
- `get_device_sdwan_monitor(adom, device)` — live SD-WAN runtime status (link state, bandwidth, SLA)

FortiManager version flag in `credentials.yaml` controls `version: "7.4"` vs `"7.6"` policy path behaviour.

### zone_mcp/ (live 4THealth API — authoritative for verdicts)

**`client.py`** — thin `requests` wrapper for 3 endpoints:
- `POST /external/api/zone/query` — traffic verdict
- `GET  /external/api/zone/zones` — zone catalogue
- `GET  /external/api/zone/policies` — policy table

**`server.py`** — FastMCP exposing 5 tools:
- `query_zone_policy(src, dst, service)` — bulk IP/CIDR verdict (supports comma/newline-separated lists)
- `get_zones()` — full zone catalogue (33 zones, live)
- `get_policies()` — raw policy table (161 policies, live)
- `find_zone_for_ip(ip)` — IP→zone resolution via self-query trick
- `check_ip_traffic(src_ip, dst_ip, service)` — **primary tool** for one-call IP verdict + zone context

### feedback_mcp/

**`store.py`** — SQLite backend (WAL mode). Schema: `feedback` table (indexed on src_zone/dst_zone/service for similarity queries) + append-only `audit_log`. Phase 4 migration path: replace `_connect()` for Postgres; all other code is DB-API 2.0 agnostic.

**`server.py`** — FastMCP exposing 5 tools:
- `record_feedback(...)` — save decision (ACCEPTED/MODIFIED/REJECTED) after each ticket
- `get_similar_cases(src_zone, dst_zone, service)` — precedent lookup; call before generating recommendations
- `get_feedback_summary(days)` — aggregate stats (acceptance rate, top zone pairs, etc.)
- `flag_for_review(recommendation_id, engineer_id, note)` — surface standards gaps
- `get_audit_log(ticket_id, engineer_id)` — read-only audit trail

### intake_mcp/

**`server.py`** — FastMCP exposing 3 tools:
- `parse_spreadsheet(file_path)` — parse .xlsx firewall request forms
- `parse_manual_entry(json_dict)` — normalise conversationally entered requests
- `describe_template()` — return expected spreadsheet structure

Both parse tools return the same `FirewallRequest` structure with `missing_fields` and `warnings` arrays. Always check these before proceeding to analysis.

### Data flow (full)

```
Engineer intake (.xlsx or conversation)
        │
   intake_mcp (normalise → FirewallRequest)
        │
   zone_mcp ──────────────── 4THealth live API
   (IP→zone, check_ip_traffic)    │ verdict
        │                         │
   fortimanager_mcp ─── FortiManager JSON-RPC
   (search existing rules, address objects)
        │
   standards_mcp (naming.yaml, review_requirements.yaml)
   (naming validation, logging check, approval chain)
        │
   feedback_mcp ──────── feedback.db (SQLite)
   (record_feedback, precedent lookup)
```

### policy_db.json structure

```json
{
  "zones": {
    "<zone_name>": { "domain", "subnets", "children", "parents", "description" }
  },
  "policies": [
    { "policy_set", "from_zone", "to_zone", "severity", "access_type", "services", "flows" }
  ]
}
```

Coverage: 40+ zones (OT, CIP-H, IT, Gas, Users, Internet domains), 74 explicit zone-pair policies.

### Verdict logic (policy_engine.py `evaluate()`)

1. If any matching policy is `block all` → **BLOCKED** (regardless of service)
2. If any matching policy is `block only` and the requested service matches → **BLOCKED**
3. If any matching policy is `allow` (and no block overrides) → **ALLOWED**
4. If no policies match → **UNKNOWN**

## Testing

Unit tests live in `tests/`. Run with `pytest -q tests/`. Test files:
- `tests/test_matching.py` — PortRange/catalog/PolicyMatcher set semantics (pure logic)
- `tests/test_insertion.py` — first-match shadowing/insertion analysis (pure logic)
- `tests/test_planner_standards.py` — risk/logging/naming decision rules
- `tests/test_engine.py` — planner models, fetch layer, and `plan_change` end-to-end with fake clients; payload validated against `render_report.validate_payload`
- `tests/test_cli_gen.py` — exact-string FortiGate CLI assertions
- `tests/test_fwanalyst_auth.py` — bearer middleware, ADOM token resolution, ContextVar injection, tool-aggregation count
- `tests/test_fortimanager_adom_guard.py` — `_require_adom()` logic and `get_adoms()` filtering
- `tests/test_rate_limit.py` — per-session call-budget middleware (window expiry, per-session isolation, 429 + Retry-After)
- `tests/test_policy_engine.py`, `tests/test_fortimanager_client.py`, `tests/test_zone_client.py`, `tests/test_zone_map.py`, `tests/test_render_report.py` — pre-existing suites

CI (`smoke-tests.yml`) runs `unit-tests` (full `pytest -q tests/` with all packages installed) and `smoke-tests` (containerised auth-aware checks via `scripts/run_smoke.py` against the unified server).

## Infrastructure

- **`Dockerfile.dev`** — dev image used by CI and local docker-compose
- **`docker-compose.yml`** — local dev: mounts repo for live edits
- **`docker-compose.ci.yml`** — CI: built image, no mounts, minimal env
- **`systemd/4tanalyst.service`** — systemd unit template for the unified server (VM deployment)
- **`scripts/start-all.sh`** — local dev startup helper
- **`scripts/smoke-test.sh`** + **`scripts/run_smoke.py`** — auth-aware health checks (port 8000: expect 401 without token, non-401 with)
- **`scripts/render_report.py`** — stdlib-only renderer invoked by `/analyze-request` Step 7. Takes a JSON payload (`--data <path>`) and writes `report.html` + `implementation.conf` under `output/<ticket_id_or_timestamp>/`. No third-party dependencies — matches `run_smoke.py`'s zero-dependency convention. Tested via `tests/test_render_report.py`.

## Credentials

`credentials.yaml` (gitignored). Copy from `credentials.yaml.example`. Structure:

```yaml
fortimanager:
  hosts:
    - host: FMG-SITE-A   # or 10.0.0.101
      api_key: "..."         # REST API Administrator's API key, sent as a Bearer header — not a password
    - host: FMG-SITE-B   # or 10.0.0.102 — secondary/failover
      api_key: "..."
  port: 443
  verify_ssl: true
  version: "7.4"             # or "7.6"

server:
  adom_restriction: true     # false = disable per-token ADOM filtering (all tokens get full access)
  auth_token: "..."          # admin/legacy token — always full access; used when FW_ANALYST_TOKEN env not set
  tokens:                    # optional per-engineer tokens with ADOM restrictions
    - token: "..."
      label: "engineer-name" # for logs/audit only
      adoms: ["OT-ADOM"]     # restrict to these ADOMs; ["*"] = unrestricted
  allowed_hosts: []          # host-header allowlist for DNS-rebinding protection

zone_policy:
  base_url: "https://4thealth.internal.example.com"
  token: "4th_..."
  verify_ssl: false          # self-signed cert
  timeout: 30.0
```

## Key blocking items before production

See `todo.md` for the full list. Top blockers:
1. **Test FortiManager connectivity** — credentials added, not yet fully validated against live FMG (planner CLI is the quickest end-to-end check)
2. **TLS / nginx reverse proxy** — bearer auth now enforced on port 8000, but transport is still plain HTTP; TLS termination required in any regulated environment (NERC CIP, HIPAA, PCI-DSS, etc.)
3. **AI inference path decision** — Bedrock vs. Anthropic direct vs. self-hosted (compliance implications for regulated/sensitive data differ)
4. **Compliance team engagement** — longest lead time item for deployments touching regulated data (NERC CIP, HIPAA, PCI-DSS, or your organization's own data-classification policy)
5. **IT/InfoSec approval for Claude Code on workstations**
6. **Populate real values** in `naming.yaml` and `review_requirements.yaml`
7. **Create `docs/zone-name-mapping.md`** — 4THealth zone names differ from FortiManager ADOM zone names

## Engineer slash commands (.claude/skills/)

- `/analyze-request` — full end-to-end: zone verdict + existing rule search + naming/logging + approval chain + generated `report.html`/`implementation.conf` under `output/` for ticket attachment
- `/check-policy` — quick `zone_mcp.check_ip_traffic` verdict for a src→dst flow
- `/validate-rule` — pre-submission FortiGate rule validation (naming + logging)
- `/generate-peer-review` — structured second-engineer sign-off package
- `/record-decision` — write audit entry to feedback_mcp
- `/missing-info` — triage incomplete requests and draft follow-up

## Phase roadmap (revised)

- **Phase 1** — Standards MCP: **complete**. Remaining: populate real values in config files, validate zone names, deploy to central VM.
- **Phase 2** — FortiManager MCP + zone_mcp: **complete** (code done; connectivity not yet tested against live systems).
- **Phase 3 (revised)** — Deploy to team + feedback collection (4–8 weeks of real data) + risk scorer. Build NetBrain MCP when API access is available.
- **Phase 4** — Recommendation engine built on feedback data; Postgres migration; engineer identity (AD/Entra token).
- **Phase 5** — mTLS hardening, Ansible change preview, HA.

## Key reference files

- `todo.md` — comprehensive gap tracker and open questions
- `highlevel-4tanalyst.md` — problem statement, success metrics, risk register
- `docs/compliance.md` — regime-agnostic data-sensitivity/compliance analysis (NERC CIP, HIPAA, PCI-DSS, SOX, GDPR) and inference path comparison
- `docs/engineer-workflow.md` — end-to-end how-to for engineers
- `docs/workstation-onboarding.md` — one-page laptop setup for engineers doing the sparse checkout (clone/config/verify only)
- `docs/architecture.md` — design decisions and data flow diagrams
- `SECURITY.md` — credential handling, sensitive data checklist
- `CONTRIBUTING.md` — how to add a new MCP server, PR guidelines

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
