"""
n8n trigger-endpoint tests: confirm gate, RoE scope gate, kill-switch,
callback_url SSRF guard, and completion-callback POST behavior.
Orchestrator.route is mocked via RunManager._invoke — no real agents run.
"""
from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.conftest_webdash import auth, client, state_dir, token  # noqa: F401

GOOD_URL = "http://localhost:5678/webhook/openelia-result"


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


@pytest.fixture
def allowlist(monkeypatch):
    """Approve 'localhost' under N8N_WEBHOOK_ALLOWLIST."""
    from secret_store import SecretStore

    monkeypatch.setattr(SecretStore, "get_secret", staticmethod(lambda key: "localhost" if key == "N8N_WEBHOOK_ALLOWLIST" else None))


def _wait_done(client, auth, run_id, tries=30):
    for _ in range(tries):
        rec = client.get(f"/api/run/{run_id}/status", headers=auth).json()
        if rec["status"] in ("done", "error"):
            return rec
        time.sleep(0.02)
    return rec


def test_trigger_requires_confirm(client, state_dir, roe, auth):
    resp = client.post("/api/n8n/trigger", headers=auth, json={"domain": "red", "target": "10.0.0.5"})
    assert resp.status_code == 400


def test_trigger_out_of_scope_is_403(client, state_dir, roe, auth):
    resp = client.post(
        "/api/n8n/trigger", headers=auth,
        json={"domain": "red", "target": "8.8.8.8", "confirm": True},
    )
    assert resp.status_code == 403


def test_trigger_blocked_when_locked(client, state_dir, roe, auth):
    from state_manager import StateManager

    StateManager(db_path=str(state_dir / "engagement.db")).set_locked(True)
    resp = client.post(
        "/api/n8n/trigger", headers=auth,
        json={"domain": "red", "target": "10.0.0.5", "confirm": True},
    )
    assert resp.status_code == 423


def test_trigger_invalid_callback_host_returns_400_run_never_starts(client, state_dir, roe, auth, mock_invoke):
    resp = client.post(
        "/api/n8n/trigger", headers=auth,
        json={
            "domain": "red", "target": "10.0.0.5", "confirm": True,
            "callback_url": "http://evil.example.com/hook",
        },
    )
    assert resp.status_code == 400
    mock_invoke.assert_not_awaited()


def test_trigger_no_token_returns_401(client, state_dir):
    resp = client.post("/api/n8n/trigger", json={"domain": "red", "target": "10.0.0.5", "confirm": True})
    assert resp.status_code == 401


def test_trigger_blue_skips_scope_gate(client, state_dir, auth, mock_invoke):
    resp = client.post(
        "/api/n8n/trigger", headers=auth,
        json={"domain": "blue", "target": "unused", "task": "triage logs", "confirm": True},
    )
    assert resp.status_code == 200
    rec = _wait_done(client, auth, resp.json()["run_id"])
    assert rec["status"] == "done"


def test_trigger_success_fires_completion_callback(client, state_dir, roe, auth, mock_invoke, allowlist):
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=MagicMock(raise_for_status=MagicMock()))

    with patch("httpx.AsyncClient", return_value=mock_client):
        resp = client.post(
            "/api/n8n/trigger", headers=auth,
            json={
                "domain": "red", "target": "10.0.0.5", "confirm": True,
                "callback_url": GOOD_URL,
            },
        )
        assert resp.status_code == 200
        run_id = resp.json()["run_id"]
        rec = _wait_done(client, auth, run_id)
        assert rec["status"] == "done"

        # _notify is fired via asyncio.create_task in the run's finally block;
        # give the event loop a beat to schedule and run it.
        for _ in range(30):
            if mock_client.post.await_count:
                break
            time.sleep(0.02)

    mock_client.post.assert_awaited_once()
    call_args = mock_client.post.await_args
    assert call_args.args[0] == GOOD_URL
    posted_payload = call_args.kwargs["json"]
    assert posted_payload["run_id"] == run_id
    assert posted_payload["status"] == "done"


def test_trigger_callback_post_failure_does_not_affect_run_status(client, state_dir, roe, auth, mock_invoke, allowlist):
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=RuntimeError("connection refused"))

    with patch("httpx.AsyncClient", return_value=mock_client):
        resp = client.post(
            "/api/n8n/trigger", headers=auth,
            json={
                "domain": "red", "target": "10.0.0.5", "confirm": True,
                "callback_url": GOOD_URL,
            },
        )
        assert resp.status_code == 200
        run_id = resp.json()["run_id"]
        rec = _wait_done(client, auth, run_id)
        # run's own status is unaffected by the callback POST failing
        assert rec["status"] == "done"

        for _ in range(30):
            if mock_client.post.await_count:
                break
            time.sleep(0.02)

    mock_client.post.assert_awaited_once()
    # rec still reflects the successful run, not a webhook error
    assert rec["error"] is None
