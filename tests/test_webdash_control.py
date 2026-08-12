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


# ---------------------------------------------------------------------------
# force_agent / agent= tests
# ---------------------------------------------------------------------------

def test_run_blue_with_valid_agent_starts(client, state_dir, roe, auth, mock_invoke):
    """POST /api/run/blue with a valid blue agent starts the run and forwards agent."""
    resp = client.post(
        "/api/run/blue",
        headers=auth,
        json={"task": "hunt", "agent": "defender_hunt", "confirm": True},
    )
    assert resp.status_code == 200
    run_id = resp.json()["run_id"]
    rec = _wait_done(client, auth, run_id)
    assert rec["status"] == "done"
    # Verify _invoke was called with agent="defender_hunt"
    assert mock_invoke.call_args.kwargs["agent"] == "defender_hunt"


def test_run_blue_wrong_domain_agent_returns_400(client, state_dir, roe, auth):
    """POST /api/run/blue with a red agent name returns 400."""
    resp = client.post(
        "/api/run/blue",
        headers=auth,
        json={"task": "hunt", "agent": "pentester_recon", "confirm": True},
    )
    assert resp.status_code == 400
    assert "pentester_recon" in resp.json()["detail"]


def test_run_red_bogus_agent_returns_400(client, state_dir, roe, auth):
    """POST /api/run/red with an unknown agent name returns 400."""
    resp = client.post(
        "/api/run/red",
        headers=auth,
        json={"target": "10.0.0.5", "agent": "bogus", "confirm": True},
    )
    assert resp.status_code == 400
    assert "bogus" in resp.json()["detail"]


def test_run_blue_no_agent_unchanged(client, state_dir, auth, mock_invoke):
    """Existing behavior: no agent field → run starts normally."""
    resp = client.post("/api/run/blue", headers=auth, json={"task": "triage logs", "confirm": True})
    assert resp.status_code == 200
    rec = _wait_done(client, auth, resp.json()["run_id"])
    assert rec["status"] == "done"
    # agent param should be None
    assert mock_invoke.call_args.kwargs["agent"] is None


# ---------------------------------------------------------------------------
# POST /api/report/brief endpoint tests
# ---------------------------------------------------------------------------

def test_report_brief_returns_markdown(client, state_dir, auth, monkeypatch):
    """POST /api/report/brief with confirm=True returns {markdown: ...}."""
    from unittest.mock import AsyncMock, patch

    with patch("agents.reporter_agent.ReporterAgent.brief", new=AsyncMock(return_value="# Brief\nTop risks.")):
        resp = client.post("/api/report/brief", headers=auth, json={"confirm": True})
    assert resp.status_code == 200
    body = resp.json()
    assert "markdown" in body
    assert body["markdown"] == "# Brief\nTop risks."


def test_report_brief_missing_confirm_returns_400(client, state_dir, auth):
    """POST /api/report/brief without confirm raises 400."""
    resp = client.post("/api/report/brief", headers=auth, json={})
    assert resp.status_code == 400


def test_report_brief_no_token_returns_401(client, state_dir):
    """POST /api/report/brief without auth token returns 401."""
    resp = client.post("/api/report/brief", json={"confirm": True})
    assert resp.status_code == 401


def test_report_brief_blocked_when_locked(client, state_dir, auth):
    """A locked engine returns a clean 423 instead of letting the agent tool loop
    raise SystemExit (which would not convert to a clean HTTP response)."""
    from state_manager import StateManager

    StateManager(db_path=str(state_dir / "engagement.db")).set_locked(True)
    resp = client.post("/api/report/brief", headers=auth, json={"confirm": True})
    assert resp.status_code == 423


# ---------------------------------------------------------------------------
# Engagement termination — graceful end + scoped rollback
# ---------------------------------------------------------------------------

def test_terminate_requires_confirm(client, state_dir, auth):
    """POST terminate without confirm raises 400."""
    eid = client.get("/api/engagements", headers=auth).json()[0]["id"]
    resp = client.post(f"/api/engagements/{eid}/terminate", headers=auth, json={})
    assert resp.status_code == 400


def test_terminate_no_token_returns_401(client, state_dir):
    """POST terminate without auth token returns 401."""
    resp = client.post("/api/engagements/ENG-X/terminate", json={"confirm": True})
    assert resp.status_code == 401


def test_terminate_unknown_id_returns_404(client, state_dir, auth):
    resp = client.post("/api/engagements/ENG-NOPE/terminate", headers=auth, json={"confirm": True})
    assert resp.status_code == 404


def test_terminate_marks_inactive_and_preserves_history(client, state_dir, auth):
    eng = client.get("/api/engagements", headers=auth).json()[0]
    assert eng["is_active"] is True
    eid = eng["id"]

    resp = client.post(f"/api/engagements/{eid}/terminate", headers=auth, json={"confirm": True})
    assert resp.status_code == 200
    body = resp.json()
    assert body["terminated"] is True and body["engagement_id"] == eid
    assert set(body["cleanup"]) == {"executed", "refused", "failed", "pending"}

    # History preserved (row still present) but no longer active.
    after = {e["id"]: e for e in client.get("/api/engagements", headers=auth).json()}
    assert eid in after
    assert after[eid]["is_active"] is False


def test_terminate_processes_rollback_queue(client, state_dir, roe, auth):
    """Terminate invokes the rollback queue scoped to THIS engagement.

    The endpoint builds a fresh StateManager, so the in-memory undo callable
    (registered during the run) is absent — the persisted row is left 'pending'
    for manual operator recovery and never auto-shelled (zero-trust). Same
    contract as the kill-switch. Asserting pending==1 proves run_all ran against
    the right engagement id.
    """
    from state_manager import StateManager

    sm = StateManager(db_path=str(state_dir / "engagement.db"))
    eid = sm.read()["engagement"]["id"]
    sm.cleanup_registry.register(
        engagement_id=eid,
        description="test cron",
        undo_command="crontab -r",
        target="10.0.0.5",
        source="pentester_persist",
        undo=lambda: None,
    )

    resp = client.post(f"/api/engagements/{eid}/terminate", headers=auth, json={"confirm": True})
    assert resp.status_code == 200
    c = resp.json()["cleanup"]
    assert c["pending"] == 1 and c["executed"] == 0
