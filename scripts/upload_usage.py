#!/usr/bin/env python3
"""Claude Code Stop hook — POST token-usage event to the 4tAnalyst analytics endpoint.

Reads the Stop event from stdin, resolves the bearer token from
.claude/mcp_servers.json (so the token is never hardcoded here),
and fires a best-effort POST to /api/usage. Failures are silently
swallowed so a network hiccup never blocks Claude Code.
"""
import json
import pathlib
import sys
import urllib.request

# ── Read Stop event from stdin ────────────────────────────────────────────────
try:
    event = json.load(sys.stdin)
except Exception:
    sys.exit(0)

stats = event.get("stats") or event.get("usage") or {}
input_tokens = int(stats.get("input_tokens") or stats.get("inputTokens") or 0)
output_tokens = int(stats.get("output_tokens") or stats.get("outputTokens") or 0)
model = event.get("model") or "claude"

if input_tokens == 0 and output_tokens == 0:
    sys.exit(0)

# ── Resolve bearer token from mcp_servers.json ───────────────────────────────
script_dir = pathlib.Path(__file__).resolve().parent.parent
mcp_config = script_dir / ".claude" / "mcp_servers.json"
try:
    config = json.loads(mcp_config.read_text())
    servers = config.get("mcpServers") or config.get("servers") or {}
    server = next(iter(servers.values()), {})
    headers_cfg = server.get("headers") or {}
    auth_header = headers_cfg.get("Authorization") or headers_cfg.get("authorization") or ""
    token = auth_header.removeprefix("Bearer ").strip()
    base_url = server.get("url", "").removesuffix("/mcp")
except Exception:
    sys.exit(0)

if not token or not base_url:
    sys.exit(0)

# ── POST usage event ──────────────────────────────────────────────────────────
payload = json.dumps({
    "input_tokens": input_tokens,
    "output_tokens": output_tokens,
    "model": model,
}).encode()

try:
    req = urllib.request.Request(
        f"{base_url}/api/usage",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    urllib.request.urlopen(req, timeout=5)
except Exception:
    pass  # best-effort — never block Claude Code
