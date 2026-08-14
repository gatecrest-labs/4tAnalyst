"""Admin authentication helpers for the web admin interface.

Provides bcrypt password hashing, users.json persistence, authentication,
in-memory rate limiting, and session-user extraction.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from pathlib import Path

import bcrypt

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password* (cost 12)."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    """Return True if *password* matches *password_hash*."""
    return bcrypt.checkpw(password.encode(), password_hash.encode())


# ---------------------------------------------------------------------------
# Users file (users.json)
# ---------------------------------------------------------------------------


def load_users(users_path: str) -> dict:
    """Load users dict from *users_path*; return {} if the file does not exist."""
    p = Path(users_path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def save_users(users_path: str, users: dict) -> None:
    """Write *users* dict to *users_path* as indented JSON."""
    Path(users_path).write_text(json.dumps(users, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def authenticate(
    username: str, password: str, users_path: str
) -> tuple[str, None] | None:
    """Return (role, None) if credentials are valid, or None on failure.

    Loads users from *users_path* on every call so file edits take effect
    immediately without a server restart.
    """
    users = load_users(users_path)
    user = users.get(username)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return (user["role"], None)


# ---------------------------------------------------------------------------
# In-memory sliding-window rate limiter (per IP / arbitrary key)
# ---------------------------------------------------------------------------

_WINDOW: int = 600  # seconds
_MAX: int = 10  # failures before blocking

_failures: dict[str, list[float]] = defaultdict(list)
_failures_lock: threading.Lock = threading.Lock()


def check_rate_limit(key: str) -> bool:
    """Return True (allowed) when fewer than _MAX failures for *key* in the last _WINDOW seconds."""
    now = time.time()
    with _failures_lock:
        _failures[key] = [t for t in _failures[key] if now - t < _WINDOW]
        return len(_failures[key]) < _MAX


def record_failure(key: str) -> None:
    """Record a failed authentication attempt for *key*."""
    with _failures_lock:
        _failures[key].append(time.time())


def clear_failures(key: str) -> None:
    """Clear all recorded failures for *key* (called after successful login)."""
    with _failures_lock:
        _failures.pop(key, None)


# ---------------------------------------------------------------------------
# Session helper
# ---------------------------------------------------------------------------


def get_session_user(request) -> dict | None:  # type: ignore[type-arg]
    """Return the user dict stored under ``session["user"]``, or None if absent.

    Expects a Starlette ``Request``; the user dict is stored by admin_routes
    at login time as ``request.session["user"] = {"username": ..., "role": ...}``.
    """
    return request.session.get("user")
