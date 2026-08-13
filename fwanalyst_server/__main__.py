"""
Entry point for the unified server.

  MCP_TRANSPORT=stdio (default)  — local development
  MCP_TRANSPORT=http             — streamable-HTTP behind static-bearer auth
                                   (FASTMCP_HOST/FASTMCP_PORT, token from
                                   FW_ANALYST_TOKEN or credentials.yaml
                                   server.auth_token; env wins)
"""

import logging
import os
import stat
import threading
import time
from pathlib import Path

import yaml
from mcp.server.transport_security import TransportSecuritySettings

from fwanalyst_server.auth import require_bearer
from fwanalyst_server.rate_limit import rate_limit
from fwanalyst_server.request_timeout import request_timeout
from fwanalyst_server.server import mcp

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).parent.parent
_DEFAULT_RATE_LIMIT_MAX = 300
_DEFAULT_RATE_LIMIT_WINDOW = 60.0


def _auth_token() -> str:
    env = os.getenv("FW_ANALYST_TOKEN", "")
    if env.strip():
        return env.strip()
    creds_path = Path(os.getenv("CREDENTIALS_FILE", str(_REPO_ROOT / "credentials.yaml")))
    if creds_path.exists():
        with open(creds_path, encoding="utf-8") as fh:
            creds = yaml.safe_load(fh) or {}
        return str(creds.get("server", {}).get("auth_token", "")).strip()
    return ""


def _check_creds_permissions(creds_path: Path, http_mode: bool) -> None:
    """Refuse (HTTP) or warn (stdio) when credentials.yaml is group/world-readable.

    The file holds FortiManager API keys and every bearer token, so on a shared
    VM its mode is part of the auth boundary. Skipped where POSIX modes are not
    meaningful (Windows), since os.stat reports them inaccurately there.
    """
    if os.name != "posix":
        return
    mode = creds_path.stat().st_mode
    if not mode & (stat.S_IRWXG | stat.S_IRWXO):
        return
    detail = (
        f"{creds_path} is group/world-accessible (mode {stat.S_IMODE(mode):04o}). "
        f"It holds FortiManager API keys and bearer tokens — run: "
        f"chmod 600 {creds_path}"
    )
    if http_mode:
        raise SystemExit(f"Refusing to serve HTTP: {detail}")
    logger.warning("Insecure credentials file permissions: %s", detail)


def _load_creds(http_mode: bool = False) -> dict:
    """Load the full credentials dict (for ADOM restriction config)."""
    creds_path = Path(os.getenv("CREDENTIALS_FILE", str(_REPO_ROOT / "credentials.yaml")))
    if creds_path.exists():
        _check_creds_permissions(creds_path, http_mode)
        with open(creds_path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


def _ssl_files(creds: dict) -> tuple[str, str] | None:
    """Return (certfile, keyfile) for direct uvicorn TLS, or None when unset.

    FW_ANALYST_SSL_CERTFILE/FW_ANALYST_SSL_KEYFILE win over credentials.yaml
    server.ssl_certfile/ssl_keyfile, matching the precedence used for the auth
    token and allowed hosts. Both or neither — half a TLS config would
    otherwise start silently on plain HTTP. See docs/tls-setup.md.
    """
    server_cfg = creds.get("server", {})
    certfile = (os.getenv("FW_ANALYST_SSL_CERTFILE", "")
                or str(server_cfg.get("ssl_certfile", "") or "")).strip()
    keyfile = (os.getenv("FW_ANALYST_SSL_KEYFILE", "")
               or str(server_cfg.get("ssl_keyfile", "") or "")).strip()
    if not certfile and not keyfile:
        return None
    if not certfile or not keyfile:
        missing = "FW_ANALYST_SSL_CERTFILE" if not certfile else "FW_ANALYST_SSL_KEYFILE"
        raise SystemExit(
            f"TLS is half-configured: {missing} (or the matching credentials.yaml "
            "server.ssl_certfile/ssl_keyfile key) is unset. Set both or neither."
        )
    return certfile, keyfile


def _allowed_hosts() -> list[str]:
    """Host-header values (for DNS-rebinding protection) accepted on the
    engineers' connection URL — e.g. "central-server:8000" or a wildcard
    port "central-server:*". Comma-separated; env wins over credentials.yaml.

    The MCP SDK's default (localhost/127.0.0.1/[::1] only) rejects every
    real engineer connecting via the deployed hostname, so this must be set
    before the server is reachable from anywhere but localhost.
    """
    env = os.getenv("FW_ANALYST_ALLOWED_HOSTS", "")
    if env.strip():
        return [h.strip() for h in env.split(",") if h.strip()]
    creds_path = Path(os.getenv("CREDENTIALS_FILE", str(_REPO_ROOT / "credentials.yaml")))
    if creds_path.exists():
        with open(creds_path, encoding="utf-8") as fh:
            creds = yaml.safe_load(fh) or {}
        hosts = creds.get("server", {}).get("allowed_hosts", [])
        if isinstance(hosts, list):
            return [str(h).strip() for h in hosts if str(h).strip()]
    return []


_CACHE_REFRESH_INTERVAL = 2700  # 45 minutes — refresh well before the 1-hour TTL


def _start_metrics_collector(db: "analytics.AnalyticsDB") -> None:
    """Collect CPU/memory/disk every 60 seconds into analytics.db."""
    def _loop() -> None:
        import psutil
        while True:
            try:
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory().percent
                disk = psutil.disk_usage("/").percent
                db.log_system_metric(cpu, mem, disk)
            except Exception as exc:
                logger.debug("Metrics collection error: %s", exc)
            time.sleep(59)  # 59s + 1s blocking cpu_percent ≈ 60s

    threading.Thread(target=_loop, name="metrics-collector", daemon=True).start()


def _start_retention_job(db: "analytics.AnalyticsDB", retention_days: int) -> None:
    """Purge analytics records older than retention_days, running daily."""
    def _loop() -> None:
        while True:
            time.sleep(86400)
            try:
                db.purge_old_records(retention_days)
                logger.info("Analytics retention purge complete (%d days).", retention_days)
            except Exception as exc:
                logger.warning("Retention purge failed: %s", exc)

    threading.Thread(target=_loop, name="retention-job", daemon=True).start()


def _start_catalog_warmup(creds: dict) -> None:
    """Pre-populate the FortiManager catalog and policy caches, then keep them warm.

    plan_change on a cold cache fetches thousands of address/service objects AND
    iterates every policy package — typically 2–3 minutes on a large ADOM. The MCP
    SSE stream has no data during that window; the client-side reader drops the
    connection with ClosedResourceError before the result arrives.

    A background daemon thread populates both caches at startup, then re-warms them
    every 45 minutes (before the 1-hour TTL expires) so they are never cold again.
    """
    fmg_conf = creds.get("fortimanager", {})
    hosts = fmg_conf.get("hosts", [])
    if not hosts:
        return

    def _warm_once(client, adoms: list[str], label: str) -> None:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        from fortimanager_mcp.query import build_catalogs, build_policy_snapshot

        logger.info("Cache warm-up (%s): refreshing %d ADOM(s) in parallel", label, len(adoms))

        def _warm_adom(adom: str) -> str:
            build_catalogs(client, adom)
            build_policy_snapshot(client, adom)
            return adom

        with ThreadPoolExecutor(max_workers=6, thread_name_prefix="warmup") as pool:
            futures = {pool.submit(_warm_adom, adom): adom for adom in adoms}
            for future in as_completed(futures):
                adom = futures[future]
                try:
                    future.result()
                    logger.info("Cache warm-up (%s): %s done", label, adom)
                except Exception as exc:
                    logger.warning("Cache warm-up (%s): %s failed — %s", label, adom, exc)

    def _loop() -> None:
        try:
            from fortimanager_mcp.client import FortiManagerClient
            from fortimanager_mcp.query import list_adoms

            primary = hosts[0]
            secondary = hosts[1] if len(hosts) > 1 else {}
            client = FortiManagerClient(
                primary_host=primary.get("host", ""),
                primary_key=primary.get("api_key", ""),
                secondary_host=secondary.get("host", ""),
                secondary_key=secondary.get("api_key", ""),
                port=fmg_conf.get("port", 443),
                verify_ssl=fmg_conf.get("verify_ssl", True),
                version=str(fmg_conf.get("version", "7.4")),
            )
            client.login()
            adoms = [a["name"] for a in list_adoms(client) if a.get("name")]

            # Initial warm-up at startup
            _warm_once(client, adoms, "startup")

            # Periodic refresh to keep caches from going cold
            while True:
                time.sleep(_CACHE_REFRESH_INTERVAL)
                _warm_once(client, adoms, "refresh")

        except Exception as exc:
            logger.warning("Cache warm-up thread failed: %s", exc)

    t = threading.Thread(target=_loop, name="catalog-warmup", daemon=True)
    t.start()


def main() -> None:
    transport = os.getenv("MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        _load_creds()  # warns (does not refuse) on loose credentials-file perms
        mcp.run()
        return

    if transport not in ("http", "streamable-http"):
        raise SystemExit(f"Unsupported MCP_TRANSPORT {transport!r} (use stdio or http)")

    # Loaded (and permission-checked) before anything binds a socket.
    creds = _load_creds(http_mode=True)
    ssl_files = _ssl_files(creds)

    import uvicorn

    host = os.getenv("FASTMCP_HOST", "0.0.0.0")
    port = int(os.getenv("FASTMCP_PORT", "8000"))
    mcp.settings.host = host
    mcp.settings.port = port

    allowed_hosts = _allowed_hosts()
    if allowed_hosts:
        mcp.settings.transport_security = TransportSecuritySettings(allowed_hosts=allowed_hosts)
    # Else: keep the SDK default (enable_dns_rebinding_protection=True,
    # allowed_hosts restricted to localhost/127.0.0.1/[::1]) — fail-closed
    # rather than silently accepting any Host header.

    # ---------- Analytics DB ----------
    data_dir = Path(os.getenv("DATA_DIR", str(_REPO_ROOT / "data")))
    data_dir.mkdir(parents=True, exist_ok=True)
    analytics_db_path = str(data_dir / "analytics.db")
    users_path = str(data_dir / "users.json")
    creds_path = str(Path(os.getenv("CREDENTIALS_FILE", str(_REPO_ROOT / "credentials.yaml"))))

    from fwanalyst_server import analytics as _analytics_mod
    analytics_db = _analytics_mod.init(analytics_db_path)

    # ---------- TokenRegistry ----------
    from fwanalyst_server.context import token_registry
    token_registry.load(creds)

    # ---------- MCP ASGI stack ----------
    mcp_app = mcp.streamable_http_app()

    from fwanalyst_server.usage_middleware import UsageMiddleware
    mcp_app = UsageMiddleware(mcp_app, analytics_db)

    max_requests = int(os.getenv("FW_ANALYST_RATE_LIMIT_MAX", str(_DEFAULT_RATE_LIMIT_MAX)))
    if max_requests > 0:
        window = float(os.getenv("FW_ANALYST_RATE_LIMIT_WINDOW_SECONDS",
                                  str(_DEFAULT_RATE_LIMIT_WINDOW)))
        mcp_app = rate_limit(mcp_app, max_requests, window)

    mcp_app = require_bearer(mcp_app, _auth_token(), creds)
    timeout = float(os.getenv("FW_ANALYST_REQUEST_TIMEOUT", "540"))
    mcp_app = request_timeout(mcp_app, timeout)

    # ---------- Admin web app (graceful degradation) ----------
    web_admin = creds.get("web_admin", {})
    secret_key = web_admin.get("secret_key", "")
    if not secret_key.strip():
        logger.warning(
            "web_admin.secret_key missing in credentials.yaml — admin UI and /api/usage "
            "are disabled. Generate one with: "
            "python -c \"import secrets; print(secrets.token_hex(32))\""
        )
        app = mcp_app
    else:
        pricing = creds.get("pricing", {})
        from fwanalyst_server.admin_app import create_admin_app
        admin_app = create_admin_app(
            secret_key=secret_key,
            db=analytics_db,
            users_path=users_path,
            creds_path=creds_path,
            pricing=pricing,
            https_only=ssl_files is not None,
        )
        from fwanalyst_server.path_dispatcher import PathDispatcher
        app = PathDispatcher(
            routes={"/admin": admin_app, "/api": admin_app},
            default=mcp_app,
        )

    # ---------- Background threads ----------
    _start_catalog_warmup(creds)
    _start_metrics_collector(analytics_db)
    retention_days = int(web_admin.get("analytics_retention_days", 90))
    _start_retention_job(analytics_db, retention_days)

    if ssl_files:
        certfile, keyfile = ssl_files
        logger.info("TLS enabled (cert %s)", certfile)
        uvicorn.run(app, host=host, port=port,
                    ssl_certfile=certfile, ssl_keyfile=keyfile)
    else:
        uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
