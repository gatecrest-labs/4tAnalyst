"""Tests for admin web routes: login/logout, dashboard auth, role enforcement."""

import pytest
from fastapi.testclient import TestClient

from fwanalyst_server.admin_app import create_admin_app
from fwanalyst_server.admin_auth import hash_password, save_users
from fwanalyst_server.analytics import AnalyticsDB


@pytest.fixture
def setup(tmp_path):
    db = AnalyticsDB(str(tmp_path / "analytics.db"))
    users_path = str(tmp_path / "users.json")
    save_users(users_path, {
        "admin": {"password_hash": hash_password("adminpass"), "role": "admin",
                  "created_at": "2026-08-13T00:00:00Z"},
        "viewer": {"password_hash": hash_password("viewpass"), "role": "viewer",
                   "created_at": "2026-08-13T00:00:00Z"},
    })
    app = create_admin_app(
        secret_key="test-secret-key-32chars-xxxxxxxxxx",
        db=db,
        users_path=users_path,
        creds_path=str(tmp_path / "credentials.yaml"),
        pricing={},
    )
    return TestClient(app, raise_server_exceptions=True)


def test_login_redirects_to_dashboard(setup):
    r = setup.post("/admin/login", data={"username": "admin", "password": "adminpass"},
                   follow_redirects=False)
    assert r.status_code == 302
    assert "/admin/dashboard" in r.headers["location"]


def test_login_wrong_password(setup):
    r = setup.post("/admin/login", data={"username": "admin", "password": "wrong"})
    assert r.status_code == 401
    assert b"Invalid credentials" in r.content


def test_dashboard_requires_auth(setup):
    r = setup.get("/admin/dashboard", follow_redirects=False)
    assert r.status_code == 302
    assert "/admin/login" in r.headers["location"]


def test_dashboard_accessible_after_login(setup):
    setup.post("/admin/login", data={"username": "admin", "password": "adminpass"})
    r = setup.get("/admin/dashboard")
    assert r.status_code == 200


def test_viewer_cannot_access_admin_tab(setup):
    setup.post("/admin/login", data={"username": "viewer", "password": "viewpass"})
    r = setup.get("/admin/adoms")
    assert r.status_code == 403


def test_logout_clears_session(setup):
    setup.post("/admin/login", data={"username": "admin", "password": "adminpass"})
    setup.get("/admin/logout")
    r = setup.get("/admin/dashboard", follow_redirects=False)
    assert r.status_code == 302
