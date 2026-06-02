"""
Monitor-endpoint tests: shapes of the read-only views + the WebSocket happy path.
Uses a seeded tmp state directory (see conftest_webdash.state_dir).
"""
from __future__ import annotations

import json

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


def test_tasks_scoped_to_active_engagement(tmp_path):
    """Only task results within the active engagement window are returned —
    older lifetime history (before `started`) is excluded."""
    from state_manager import StateManager
    from webdash.data import DashboardData

    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    sm.initialize_engagement("10.0.0.9", "scope")
    started = sm.read()["engagement"]["started"]

    (tmp_path / "task_results.jsonl").write_text(
        json.dumps({"task_id": "old", "agent_name": "pentester_recon",
                    "status": "success", "completed_at": "2020-01-01T00:00:00+00:00"}) + "\n"
        + json.dumps({"task_id": "new", "agent_name": "pentester_recon",
                      "status": "error", "completed_at": started}) + "\n"
    )

    rows = DashboardData(state_dir=tmp_path).tasks()
    assert {r["task_id"] for r in rows} == {"new"}


def test_tasks_empty_without_active_engagement(tmp_path):
    """No active engagement → idle (empty), even if the log has rows."""
    from webdash.data import DashboardData

    (tmp_path / "task_results.jsonl").write_text(
        json.dumps({"task_id": "x", "agent_name": "pentester_recon",
                    "status": "success", "completed_at": "2026-06-01T00:00:00+00:00"}) + "\n"
    )
    assert DashboardData(state_dir=tmp_path).tasks() == []


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


def test_roe_partial_file_backfills_all_keys(client, state_dir, auth, tmp_path, monkeypatch):
    """A roe.json that omits some whitelisted keys → response still has ALL four
    keys (backfilled), so the frontend never sees an undefined array."""
    roe_file = tmp_path / "roe_partial.json"
    # Only authorized_subnets present; the other three keys are omitted.
    roe_file.write_text('{"authorized_subnets": ["10.0.0.0/24"]}')
    monkeypatch.setenv("OPENELIA_ROE_PATH", str(roe_file))

    resp = client.get("/api/roe", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == _ROE_WHITELIST
    assert body["authorized_subnets"] == ["10.0.0.0/24"]
    assert body["blacklisted_ips"] == []
    assert body["prohibited_tools"] == []
    assert body["quiet_hours"] is None


# --- /api/engagements tests ------------------------------------------------- #

def test_engagements_requires_token(client, state_dir):
    """No token → 401."""
    resp = client.get("/api/engagements")
    assert resp.status_code == 401


def test_engagements_returns_list_with_active_engagement(client, state_dir, auth):
    """Valid token + seeded state_dir → 200, list with the seeded engagement."""
    resp = client.get("/api/engagements", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) >= 1
    first = body[0]
    assert first["target"] == "10.0.0.5"
    assert first["is_active"] is True
    # Shape: required keys present
    for key in ("id", "target", "started", "current_phase", "is_active", "is_locked"):
        assert key in first, f"Missing key: {key}"


def test_engagements_missing_db_returns_empty(client, auth, tmp_path, monkeypatch):
    """State dir with no DB → empty list, not an error."""
    monkeypatch.setenv("OPENELIA_STATE_DIR", str(tmp_path))
    monkeypatch.setattr("webdash.security.current_token", lambda: "test-token-abc123")
    resp = client.get("/api/engagements", headers=auth)
    assert resp.status_code == 200
    assert resp.json() == []


# --- /api/adversaries tests ------------------------------------------------- #

_ADVERSARY_WHITELIST = frozenset(
    {"name", "alias", "description", "preferred_ttps", "tools", "stealth_required", "rationale"}
)

_ADVERSARY_EXTRA_KEYS = ("internal_id", "secret_opsec_note", "handler_email")


def _seed_adversary_dir(tmp_path) -> str:
    """Write one minimal adversary profile and return the dir path as str."""
    profile = {
        "name": "APT-TEST",
        "alias": "Ghost Bear",
        "description": "A fictional test APT group.",
        "preferred_ttps": ["T1059", "T1078"],
        "tools": ["mimikatz", "cobalt_strike"],
        "stealth_required": True,
        "rationale": "Target financial sector.",
        # Extra non-whitelisted keys — must NOT appear in responses.
        "internal_id": "secret-123",
        "secret_opsec_note": "handler channel on Signal",
        "handler_email": "ops@apt-test.evil",
    }
    adv_dir = tmp_path / "adversaries"
    adv_dir.mkdir()
    (adv_dir / "apt-test.json").write_text(json.dumps(profile))
    return str(adv_dir)


def test_adversaries_requires_token(client, state_dir):
    """No token → 401."""
    resp = client.get("/api/adversaries")
    assert resp.status_code == 401


def test_adversaries_returns_whitelisted_profile(client, auth, tmp_path, monkeypatch):
    """Valid token + seeded adversaries dir → 200, profile fields whitelisted."""
    adv_dir = _seed_adversary_dir(tmp_path)
    monkeypatch.setenv("OPENELIA_ADVERSARIES_DIR", adv_dir)

    resp = client.get("/api/adversaries", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) == 1
    profile = body[0]

    # All returned keys must be in the whitelist
    assert set(profile.keys()) <= _ADVERSARY_WHITELIST, (
        f"Non-whitelisted keys leaked: {set(profile.keys()) - _ADVERSARY_WHITELIST}"
    )
    # Core whitelisted fields are present
    assert profile["name"] == "APT-TEST"
    assert "T1059" in profile["preferred_ttps"]
    assert profile["stealth_required"] is True

    # Extra keys must NOT appear
    for extra_key in _ADVERSARY_EXTRA_KEYS:
        assert extra_key not in profile, f"Sensitive key '{extra_key}' leaked in response"


def test_adversaries_missing_dir_returns_empty(client, auth, tmp_path, monkeypatch):
    """Non-existent adversaries dir → empty list, not an error."""
    monkeypatch.setenv("OPENELIA_ADVERSARIES_DIR", str(tmp_path / "nonexistent_adversaries"))
    resp = client.get("/api/adversaries", headers=auth)
    assert resp.status_code == 200
    assert resp.json() == []


# --- /api/system tests ------------------------------------------------------ #

def test_system_requires_token(client, state_dir):
    """No token → 401."""
    resp = client.get("/api/system")
    assert resp.status_code == 401


def test_system_returns_status_with_active_engagement(client, state_dir, auth):
    """Valid token + seeded state_dir → 200, gateway running, active_engagements >= 1."""
    resp = client.get("/api/system", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert body["gateway"] == "running"
    assert body["active_engagements"] >= 1


def test_system_no_db_active_zero(client, auth, tmp_path, monkeypatch):
    """State dir with no DB → active_engagements == 0."""
    monkeypatch.setenv("OPENELIA_STATE_DIR", str(tmp_path))
    monkeypatch.setattr("webdash.security.current_token", lambda: "test-token-abc123")
    resp = client.get("/api/system", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert body["gateway"] == "running"
    assert body["active_engagements"] == 0
