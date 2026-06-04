"""
Control-endpoint tests: confirm gate, RoE scope gate, kill-switch, background run
lifecycle, single-active-run conflict. Orchestrator.route is mocked via
RunManager._invoke — no real agents run.
"""
from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock

import pytest

from tests.conftest_webdash import auth, client, state_dir, token  # noqa: F401


@pytest.fixture(autouse=True)
def _reset_runner_and_cache():
    from security_manager import ScopeValidator
    from webdash.runner import _manager

    _manager._runs.clear()
    _manager._active = None
    ScopeValidator._resolution_cache.clear()
    yield
    _manager._runs.clear()
    _manager._active = None
    ScopeValidator._resolution_cache.clear()


@pytest.fixture
def roe(tmp_path, monkeypatch):
    p = tmp_path / "roe.json"
    p.write_text(
        json.dumps(
            {
                "authorized_subnets": ["10.0.0.0/24"],
                "blacklisted_ips": [],
                "prohibited_tools": [],
                "quiet_hours": {"enabled": False},
            }
        )
    )
    monkeypatch.setenv("OPENELIA_ROE_PATH", str(p))
    return p


@pytest.fixture
def mock_invoke(monkeypatch):
    m = AsyncMock(return_value={"domain": "red", "confidence": 1.0, "reason": "mock"})
    from webdash import runner

    monkeypatch.setattr(runner._manager, "_invoke", m)
    return m


def _wait_done(client, auth, run_id, tries=30):
    for _ in range(tries):
        rec = client.get(f"/api/run/{run_id}/status", headers=auth).json()
        if rec["status"] in ("done", "error"):
            return rec
        time.sleep(0.02)
    return rec


def test_run_red_requires_confirm(client, state_dir, roe, auth):
    resp = client.post("/api/run/red", headers=auth, json={"target": "10.0.0.5"})
    assert resp.status_code == 400


def test_run_red_out_of_scope_is_403(client, state_dir, roe, auth):
    resp = client.post("/api/run/red", headers=auth, json={"target": "8.8.8.8", "confirm": True})
    assert resp.status_code == 403


def test_run_red_in_scope_starts_and_completes(client, state_dir, roe, auth, mock_invoke):
    resp = client.post("/api/run/red", headers=auth, json={"target": "10.0.0.5", "confirm": True})
    assert resp.status_code == 200
    run_id = resp.json()["run_id"]
    rec = _wait_done(client, auth, run_id)
    assert rec["status"] == "done"
    assert rec["result"]["domain"] == "red"
    mock_invoke.assert_awaited()


def test_run_red_blocked_when_locked(client, state_dir, roe, auth):
    from state_manager import StateManager

    StateManager(db_path=str(state_dir / "engagement.db")).set_locked(True)
    resp = client.post("/api/run/red", headers=auth, json={"target": "10.0.0.5", "confirm": True})
    assert resp.status_code == 423


def test_run_blue_starts_without_scope(client, state_dir, auth, mock_invoke):
    resp = client.post("/api/run/blue", headers=auth, json={"task": "triage logs", "confirm": True})
    assert resp.status_code == 200
    rec = _wait_done(client, auth, resp.json()["run_id"])
    assert rec["status"] == "done"


def test_second_run_conflicts(client, state_dir, roe, auth):
    from webdash.runner import _manager

    _manager._runs["busy"] = {"run_id": "busy", "status": "running"}
    _manager._active = "busy"
    resp = client.post("/api/run/red", headers=auth, json={"target": "10.0.0.5", "confirm": True})
    assert resp.status_code == 409


def test_lock_then_unlock_flips_state(client, state_dir, auth):
    lock_resp = client.post("/api/lock", headers=auth, json={"confirm": True}).json()
    assert lock_resp["locked"] is True
    # lock now also reports the rollback-registry run summary
    assert set(lock_resp["cleanup"]) == {"executed", "refused", "failed", "pending"}
    assert client.get("/api/state", headers=auth).json()["engagement"]["is_locked"] is True
    assert client.post("/api/unlock", headers=auth, json={"confirm": True}).json() == {"locked": False}
    assert client.get("/api/state", headers=auth).json()["engagement"]["is_locked"] is False


def test_lock_requires_confirm(client, state_dir, auth):
    assert client.post("/api/lock", headers=auth, json={}).status_code == 400


def test_run_status_unknown_is_404(client, state_dir, auth):
    assert client.get("/api/run/nope/status", headers=auth).status_code == 404


def test_run_purple_in_scope_starts(client, state_dir, roe, auth, mock_invoke):
    resp = client.post("/api/run/purple", headers=auth, json={"target": "10.0.0.7", "confirm": True})
    assert resp.status_code == 200
    rec = _wait_done(client, auth, resp.json()["run_id"])
    assert rec["status"] == "done"
    assert rec["domain"] == "purple"


def test_run_purple_out_of_scope_is_403(client, state_dir, roe, auth):
    resp = client.post("/api/run/purple", headers=auth, json={"target": "1.1.1.1", "confirm": True})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/ioc/parse endpoint tests
# ---------------------------------------------------------------------------

def test_ioc_parse_valid_list_returns_brief(client, state_dir, auth):
    content = "\n".join([
        "198.51.100.5",
        "evil.example.org",
        "https://c2.example.com/beacon",
    ])
    resp = client.post("/api/ioc/parse", headers=auth, json={"content": content})
    assert resp.status_code == 200
    body = resp.json()
    assert body["counts"]["iocs"] > 0
    assert isinstance(body["hunt_task"], str)
    assert len(body["hunt_task"]) > 0


def test_ioc_parse_all_invalid_returns_400(client, state_dir, auth):
    resp = client.post("/api/ioc/parse", headers=auth, json={"content": "# comment only\n\n"})
    assert resp.status_code == 400


def test_ioc_parse_missing_token_returns_401(client, state_dir):
    content = "10.0.0.1\nevil.example.org"
    resp = client.post("/api/ioc/parse", json={"content": content})
    assert resp.status_code == 401
