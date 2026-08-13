"""Tests for fwanalyst_server.admin_auth and token_registry hot-reload."""

import json
import time

import pytest
from pathlib import Path
from fwanalyst_server.admin_auth import (
    hash_password,
    verify_password,
    load_users,
    save_users,
    authenticate,
    check_rate_limit,
    record_failure,
    clear_failures,
)


# ---------------------------------------------------------------------------
# Test isolation: token_registry is a module-level singleton. Ensure any state
# set during test_auth_hot_reload does not leak into test_fwanalyst_auth.py.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_token_registry():
    """Reset token_registry._tokens to None after each test."""
    yield
    from fwanalyst_server.context import token_registry
    with token_registry._lock:
        token_registry._tokens = None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def users_file(tmp_path):
    path = tmp_path / "users.json"
    users = {
        "alice": {
            "password_hash": hash_password("correct"),
            "role": "admin",
            "created_at": "2026-08-13T00:00:00Z",
        }
    }
    path.write_text(json.dumps(users))
    return str(path)


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def test_hash_and_verify():
    h = hash_password("secret")
    assert verify_password("secret", h)
    assert not verify_password("wrong", h)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_authenticate_success(users_file):
    assert authenticate("alice", "correct", users_file) == ("admin", None)


def test_authenticate_wrong_password(users_file):
    assert authenticate("alice", "bad", users_file) is None


def test_authenticate_unknown_user(users_file):
    assert authenticate("nobody", "any", users_file) is None


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def test_rate_limit_blocks_after_ten():
    key = f"test-{time.time()}"
    for _ in range(10):
        record_failure(key)
    assert not check_rate_limit(key)
    clear_failures(key)
    assert check_rate_limit(key)


# ---------------------------------------------------------------------------
# token_registry hot-reload integration
# ---------------------------------------------------------------------------


def test_auth_hot_reload(tmp_path):
    from fwanalyst_server.context import token_registry

    creds = {"server": {"adom_restriction": True, "tokens": [
        {"token": "mytoken", "label": "eng", "adoms": ["OT-ADOM"]}
    ]}}
    token_registry.load(creds)
    from fwanalyst_server.auth import _resolve_allowed_adoms
    result = _resolve_allowed_adoms("mytoken", creds)
    assert result == {"OT-ADOM"}
    # hot update
    token_registry.update_tokens([{"token": "mytoken", "label": "eng", "adoms": ["IT-ADOM"]}])
    result2 = _resolve_allowed_adoms("mytoken", creds)
    assert result2 == {"IT-ADOM"}
    # cleanup
    token_registry.update_tokens([])
    # Note: _reset_token_registry autouse fixture restores _tokens to None after this test
