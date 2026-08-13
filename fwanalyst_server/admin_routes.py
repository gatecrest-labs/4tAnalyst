"""Admin web routes: login/logout, dashboard, graph, admin tab, and API endpoints.

All session-protected routes call _user_or_redirect() which returns a user dict
on success or a RedirectResponse on failure. JSON API routes return 401/403 JSON
on auth failure instead of a redirect.

The /api/usage endpoint is authenticated by MCP bearer token (not session cookie)
to allow Claude Code to post token-usage events from within tool calls.
"""

from __future__ import annotations

import hmac
import logging
import time
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from fwanalyst_server.admin_auth import (
    authenticate,
    check_rate_limit,
    clear_failures,
    get_session_user,
    record_failure,
)
from fwanalyst_server.analytics import AnalyticsDB


def create_router(
    templates: Jinja2Templates,
    db: AnalyticsDB,
    users_path: str,
    creds_path: str,
    pricing: dict,
) -> APIRouter:
    """Build and return an APIRouter with all admin routes.

    Args:
        templates: Configured Jinja2Templates instance.
        db: AnalyticsDB for metrics/usage queries.
        users_path: Path to users.json.
        creds_path: Path to credentials.yaml.
        pricing: Model pricing configuration dict.

    Returns:
        APIRouter with all routes registered.
    """
    router = APIRouter()

    def _user_or_redirect(request: Request) -> dict | RedirectResponse:
        """Return session user dict or a redirect to /admin/login."""
        user = get_session_user(request)
        if not user:
            return RedirectResponse("/admin/login", status_code=302)
        # Enforce absolute session limit (24h)
        if time.time() - request.session.get("login_at", 0) > 86400:
            request.session.clear()
            return RedirectResponse("/admin/login", status_code=302)
        return user

    # ---------- Root redirect ----------

    @router.get("/admin")
    async def admin_root() -> Any:
        return RedirectResponse("/admin/login", status_code=302)

    # ---------- Login / Logout ----------

    @router.get("/admin/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Any:
        if get_session_user(request):
            return RedirectResponse("/admin/dashboard", status_code=302)
        return templates.TemplateResponse(request, "login.html", {"error": None})

    @router.post("/admin/login")
    async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ) -> Any:
        ip = request.client.host if request.client else "unknown"
        if not check_rate_limit(ip) or not check_rate_limit(username):
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": "Too many failed attempts. Try again later."},
                status_code=429,
            )
        result = authenticate(username, password, users_path)
        if result is None:
            record_failure(ip)
            record_failure(username)
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": "Invalid credentials."},
                status_code=401,
            )
        clear_failures(ip)
        clear_failures(username)
        role, _ = result
        request.session["user"] = {"username": username, "role": role}
        request.session["login_at"] = int(time.time())
        return RedirectResponse("/admin/dashboard", status_code=302)

    @router.get("/admin/logout")
    async def logout(request: Request) -> Any:
        request.session.clear()
        return RedirectResponse("/admin/login", status_code=302)

    # ---------- Dashboard ----------

    @router.get("/admin/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request) -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return user
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {"user": user, "active_tab": "dashboard"},
        )

    @router.get("/api/admin/metrics")
    async def metrics_api(request: Request, range: str = "1h") -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        range_map = {
            "1h": 3600,
            "4h": 14400,
            "12h": 43200,
            "1d": 86400,
            "7d": 604800,
        }
        seconds = range_map.get(range, 3600)
        current = db.get_current_metrics() or {
            "cpu_pct": 0.0,
            "mem_pct": 0.0,
            "disk_pct": 0.0,
        }
        history = db.query_metrics(range_seconds=seconds)
        return {"current": current, "history": history}

    # ---------- Graph ----------

    @router.get("/admin/graph", response_class=HTMLResponse)
    async def graph(request: Request) -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return user
        return templates.TemplateResponse(
            request,
            "graph.html",
            {"user": user, "active_tab": "graph"},
        )

    @router.get("/api/admin/usage")
    async def usage_api(request: Request, range: str = "86400") -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            seconds = int(range)
        except ValueError:
            seconds = 86400
        return db.bucket_usage(range_seconds=seconds)

    # ---------- Admin tab ----------

    @router.get("/admin/adoms", response_class=HTMLResponse)
    async def admin_tab(request: Request) -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return user
        if user.get("role") != "admin":
            return HTMLResponse("Forbidden", status_code=403)
        return templates.TemplateResponse(
            request,
            "admin_tab.html",
            {"user": user, "active_tab": "adoms"},
        )

    # ---------- User management API ----------

    @router.get("/api/admin/users")
    async def list_users_api(request: Request) -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if user.get("role") != "admin":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        from fwanalyst_server.admin_auth import load_users

        users = load_users(users_path)
        return [
            {"username": k, "role": v["role"], "created_at": v.get("created_at", "")}
            for k, v in users.items()
        ]

    @router.post("/api/admin/users")
    async def create_user_api(request: Request) -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if user.get("role") != "admin":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        body = await request.json()
        from fwanalyst_server.admin_cli import create_user

        try:
            create_user(body["username"], body["role"], body["password"], users_path)
        except ValueError as e:
            return JSONResponse({"detail": str(e)}, status_code=409)
        return JSONResponse({}, status_code=201)

    @router.delete("/api/admin/users/{username}")
    async def delete_user_api(request: Request, username: str) -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if user.get("role") != "admin":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if user.get("username") == username:
            return JSONResponse({"detail": "Cannot delete yourself."}, status_code=400)
        from fwanalyst_server.admin_cli import delete_user

        try:
            delete_user(username, users_path)
        except KeyError as e:
            return JSONResponse({"detail": str(e)}, status_code=404)
        return JSONResponse({}, status_code=204)

    @router.put("/api/admin/users/{username}/role")
    async def change_role_api(request: Request, username: str) -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if user.get("role") != "admin":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        body = await request.json()
        from fwanalyst_server.admin_auth import load_users, save_users

        users = load_users(users_path)
        if username not in users:
            return JSONResponse({"detail": "Not found."}, status_code=404)
        users[username]["role"] = body["role"]
        save_users(users_path, users)
        return JSONResponse({})

    @router.put("/api/admin/users/{username}/password")
    async def reset_pw_api(request: Request, username: str) -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if user.get("role") != "admin":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        body = await request.json()
        from fwanalyst_server.admin_cli import reset_password

        try:
            reset_password(username, body["password"], users_path)
        except KeyError as e:
            return JSONResponse({"detail": str(e)}, status_code=404)
        return JSONResponse({})

    # ---------- Token / ADOM management API ----------

    @router.get("/api/admin/tokens")
    async def list_tokens_api(request: Request) -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if user.get("role") != "admin":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        creds = _load_creds(creds_path)
        tokens = creds.get("server", {}).get("tokens", [])
        return [
            {
                "label": t.get("label", ""),
                "token_suffix": t.get("token", "")[-6:],
                "adoms": t.get("adoms", []),
            }
            for t in tokens
        ]

    @router.put("/api/admin/tokens/{idx}/adoms")
    async def update_token_adoms(request: Request, idx: int) -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if user.get("role") != "admin":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        body = await request.json()
        creds = _load_creds(creds_path)
        tokens = creds.get("server", {}).get("tokens", [])
        if idx < 0 or idx >= len(tokens):
            return JSONResponse({"detail": "Index out of range."}, status_code=404)
        tokens[idx]["adoms"] = body["adoms"]
        _save_creds(creds_path, creds)
        from fwanalyst_server.context import token_registry

        token_registry.update_tokens(tokens)
        return JSONResponse({})

    @router.delete("/api/admin/tokens/{idx}")
    async def delete_token(request: Request, idx: int) -> Any:
        user = _user_or_redirect(request)
        if isinstance(user, RedirectResponse):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if user.get("role") != "admin":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        creds = _load_creds(creds_path)
        tokens = creds.get("server", {}).get("tokens", [])
        if idx < 0 or idx >= len(tokens):
            return JSONResponse({"detail": "Index out of range."}, status_code=404)
        tokens.pop(idx)
        _save_creds(creds_path, creds)
        from fwanalyst_server.context import token_registry

        token_registry.update_tokens(tokens)
        return JSONResponse({}, status_code=204)

    # ---------- Usage event endpoint (bearer-authenticated, no session) ----------

    @router.post("/api/usage")
    async def record_usage(request: Request) -> Any:
        """Accept token-usage events from Claude Code sessions.

        Authenticated by MCP bearer token, not session cookie. Resolves the
        token to its label for per-engineer analytics attribution.
        """
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        supplied = auth.removeprefix("Bearer ").strip()

        # Resolve token label from registry or creds
        from fwanalyst_server.context import token_registry

        creds = _load_creds(creds_path)
        tokens = token_registry.get_tokens()
        if tokens is None:
            tokens = creds.get("server", {}).get("tokens", [])

        label = "-"
        for t in tokens:
            if hmac.compare_digest(
                supplied.encode(), t.get("token", "").encode()
            ):
                label = t.get("label", "-")
                break

        if label == "-":
            # Check primary admin token
            primary = creds.get("server", {}).get("auth_token", "")
            if primary and hmac.compare_digest(supplied.encode(), primary.encode()):
                label = "admin"
            else:
                return JSONResponse({"error": "unauthorized"}, status_code=401)

        body = await request.json()
        input_tokens = int(body.get("input_tokens", 0))
        output_tokens = int(body.get("output_tokens", 0))
        model = body.get("model") or "default"
        price_key = model if model in pricing else "default"
        price = pricing.get(price_key, {})
        cost = (
            input_tokens * price.get("input_per_million", 0) / 1_000_000
            + output_tokens * price.get("output_per_million", 0) / 1_000_000
        )
        db.log_usage_event(
            label,
            body.get("session_id"),
            input_tokens,
            output_tokens,
            model,
            cost,
        )
        return JSONResponse({}, status_code=204)

    return router


# ---------- Credentials helpers ----------


def _load_creds(creds_path: str) -> dict:
    """Load credentials.yaml; return empty dict if file does not exist."""
    p = Path(creds_path)
    if not p.exists():
        return {}
    with open(p, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _save_creds(creds_path: str, creds: dict) -> None:
    """Write creds dict back to credentials.yaml."""
    logger.warning("Writing credentials.yaml — inline comments will be stripped by yaml.dump()")
    with open(creds_path, "w", encoding="utf-8") as fh:
        yaml.dump(creds, fh, default_flow_style=False, allow_unicode=True)
