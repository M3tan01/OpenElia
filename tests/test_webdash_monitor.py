"""
Monitor-endpoint tests: shapes of the read-only views + the WebSocket happy path.
Uses a seeded tmp state directory (see conftest_webdash.state_dir).
"""
from __future__ import annotations

from tests.conftest_webdash import auth, client, state_dir, token  # noqa: F401


def test_state_returns_engagement(client, state_dir, auth):
    body = client.get("/api/state", headers=auth).json()
    assert body["engagement"]["target"] == "10.0.0.5"
    assert any(f["mitre_ttp"] == "T1059" for f in body["findings"])


def test_audit_returns_events_and_chain_ok(client, state_dir, auth):
    body = client.get("/api/audit", headers=auth).json()
    assert body["count"] >= 1
    assert body["chain_ok"] is True  # untampered seeded log
    assert any(e["status"] == "LLM_CALL" for e in body["events"])


def test_tasks_returns_results(client, state_dir, auth):
    body = client.get("/api/tasks", headers=auth).json()
    assert isinstance(body, list)
    assert body[0]["agent_name"] == "pentester_recon"


def test_graph_returns_nodes_and_links(client, state_dir, auth):
    body = client.get("/api/graph", headers=auth).json()
    assert body["summary"]["hosts"] == 1
    assert body["summary"]["services"] == 1
    node_ids = {n["id"] for n in body["nodes"]}
    assert "10.0.0.5" in node_ids
    assert any(link["source"] == "10.0.0.5" for link in body["links"])


def test_cost_returns_summary_and_series(client, state_dir, auth):
    body = client.get("/api/cost", headers=auth).json()
    assert "summary" in body and "budget_remaining" in body["summary"]
    assert body["series"][0]["session"] == "20260601_0000"
    assert body["series"][0]["calls"] == 3


def test_heatmap_returns_dict(client, state_dir, auth):
    # mitre_attack.json may be absent → endpoint still returns a dict (error field).
    body = client.get("/api/heatmap", headers=auth).json()
    assert isinstance(body, dict)


def test_chain_verify_endpoint(client, state_dir, auth):
    body = client.get("/api/chain/verify", headers=auth).json()
    assert body["chain_ok"] is True


def test_models_never_leaks_api_keys(client, state_dir, auth):
    body = client.get("/api/models", headers=auth).json()
    assert "config" in body
    assert "pentester_recon" in body["agents"]["red"]
    # No resolved secret should ever appear in the payload.
    blob = str(body).lower()
    assert "api_key" not in blob
    assert "sk-" not in blob


def test_websocket_snapshot_with_valid_token(client, state_dir, token):
    with client.websocket_connect(f"/api/stream?token={token}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "snapshot"
        assert msg["state"]["engagement"]["target"] == "10.0.0.5"


# --- /api/roe tests --------------------------------------------------------- #

_ROE_WHITELIST = {"authorized_subnets", "blacklisted_ips", "prohibited_tools", "quiet_hours"}


def test_roe_requires_token(client, state_dir):
    """No token → 401."""
    resp = client.get("/api/roe")
    assert resp.status_code == 401


def test_roe_with_valid_token_returns_whitelisted_keys(client, state_dir, auth, tmp_path, monkeypatch):
    """Valid token + well-formed roe.json → 200, only whitelisted keys present."""
    roe_file = tmp_path / "roe.json"
    roe_file.write_text(
        '{"authorized_subnets": ["10.0.0.0/24"], "blacklisted_ips": ["10.0.0.1"], '
        '"prohibited_tools": ["brute_force"], "quiet_hours": null}'
    )
    monkeypatch.setenv("OPENELIA_ROE_PATH", str(roe_file))

    resp = client.get("/api/roe", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) <= _ROE_WHITELIST


def test_roe_drops_sensitive_extra_keys(client, state_dir, auth, tmp_path, monkeypatch):
    """Extra sensitive keys in roe.json MUST NOT appear in the response."""
    roe_file = tmp_path / "roe_sensitive.json"
    roe_file.write_text(
        '{"authorized_subnets": ["10.0.0.0/24"], "blacklisted_ips": [], '
        '"prohibited_tools": [], "quiet_hours": null, '
        '"secret_token": "xyz", "api_key": "supersecret", "password": "hunter2"}'
    )
    monkeypatch.setenv("OPENELIA_ROE_PATH", str(roe_file))

    resp = client.get("/api/roe", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    # Whitelisted keys only
    assert set(body.keys()) <= _ROE_WHITELIST
    # Sensitive extra keys must not appear
    assert "secret_token" not in body
    assert "api_key" not in body
    assert "password" not in body


def test_roe_missing_file_returns_sentinel(client, state_dir, auth, tmp_path, monkeypatch):
    """Missing roe file → 200 with empty sentinel (no exception raised)."""
    monkeypatch.setenv("OPENELIA_ROE_PATH", str(tmp_path / "nonexistent_roe.json"))

    resp = client.get("/api/roe", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) <= _ROE_WHITELIST
