import pytest
from fastapi.testclient import TestClient

from fwanalyst_server.admin_app import create_admin_app
from fwanalyst_server.admin_auth import save_users
from fwanalyst_server.analytics import AnalyticsDB


@pytest.fixture
def client(tmp_path):
    db = AnalyticsDB(str(tmp_path / "analytics.db"))
    users_path = str(tmp_path / "users.json")
    save_users(users_path, {})
    creds_path = str(tmp_path / "credentials.yaml")
    import yaml
    with open(creds_path, "w") as f:
        yaml.dump({"server": {"auth_token": "admintoken", "tokens": [
            {"token": "engtoken", "label": "eng1", "adoms": ["OT-ADOM"]}
        ]}}, f)
    pricing = {"default": {"input_per_million": 3.0, "output_per_million": 15.0}}
    app = create_admin_app(secret_key="test-secret-x32chars-xxxxxxxxxx",
                           db=db, users_path=users_path, creds_path=creds_path, pricing=pricing)
    return TestClient(app), db


def test_usage_endpoint_accepts_named_token(client):
    c, db = client
    r = c.post("/api/usage",
               headers={"Authorization": "Bearer engtoken"},
               json={"session_id": "s1", "input_tokens": 1000, "output_tokens": 500, "model": "default"})
    assert r.status_code == 204
    db._queue.join()
    rows = db.query_usage_events(range_seconds=3600)
    assert len(rows) == 1
    assert rows[0]["token_label"] == "eng1"
    assert rows[0]["input_tokens"] == 1000
    assert rows[0]["estimated_cost"] == pytest.approx(1000 * 3.0 / 1_000_000 + 500 * 15.0 / 1_000_000)


def test_usage_endpoint_rejects_bad_token(client):
    c, db = client
    r = c.post("/api/usage",
               headers={"Authorization": "Bearer badtoken"},
               json={"session_id": "s2", "input_tokens": 100, "output_tokens": 50, "model": "default"})
    assert r.status_code == 401


def test_usage_endpoint_accepts_admin_token(client):
    c, db = client
    r = c.post("/api/usage",
               headers={"Authorization": "Bearer admintoken"},
               json={"session_id": "s3", "input_tokens": 200, "output_tokens": 100, "model": "default"})
    assert r.status_code == 204
