"""FastAPI admin web application factory.

Creates a self-contained FastAPI app with session middleware, static files,
Jinja2 templates, and all admin routes. Consumed by __main__.py (Task 8).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from fwanalyst_server.analytics import AnalyticsDB

_HERE = Path(__file__).parent
TEMPLATES_DIR = _HERE / "templates"
STATIC_DIR = _HERE / "static"


def create_admin_app(
    secret_key: str,
    db: AnalyticsDB,
    users_path: str,
    creds_path: str,
    pricing: dict,
    https_only: bool = False,
) -> FastAPI:
    """Create and return a FastAPI admin application.

    Args:
        secret_key: Secret key for Starlette session cookie signing (min 32 chars).
        db: AnalyticsDB instance for metrics and usage data.
        users_path: Absolute path to users.json file.
        creds_path: Absolute path to credentials.yaml file.
        pricing: Dict mapping model name to pricing config
                 (keys: input_per_million, output_per_million).
        https_only: Set True when TLS is configured so the session cookie
                    carries the Secure flag.

    Returns:
        Configured FastAPI application with all admin routes mounted.
    """
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret_key,
        max_age=86400,
        https_only=https_only,
        same_site="lax",
    )
    app.mount(
        "/admin/static",
        StaticFiles(directory=str(STATIC_DIR)),
        name="static",
    )
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    from fwanalyst_server.admin_routes import create_router

    app.include_router(create_router(templates, db, users_path, creds_path, pricing))

    return app
