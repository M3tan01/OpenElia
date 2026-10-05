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
# POST /api/report/full endpoint tests — full engagement report (MITRE heatmap
# + forensic chain of custody). Mirrors /report/brief guards; calls
# ReporterAgent.run() instead of .brief().
# ---------------------------------------------------------------------------

def test_report_full_returns_markdown(client, state_dir, auth):
    """POST /api/report/full with confirm=True returns {markdown: ...}."""
    from unittest.mock import AsyncMock, patch

    with patch("agents.reporter_agent.ReporterAgent.run", new=AsyncMock(return_value="# Full Report\nHeatmap + CoC.")):
        resp = client.post("/api/report/full", headers=auth, json={"confirm": True})
    assert resp.status_code == 200
    body = resp.json()
    assert "markdown" in body
    assert body["markdown"] == "# Full Report\nHeatmap + CoC."


def test_report_full_missing_confirm_returns_400(client, state_dir, auth):
    """POST /api/report/full without confirm raises 400."""
    resp = client.post("/api/report/full", headers=auth, json={})
    assert resp.status_code == 400


def test_report_full_no_token_returns_401(client, state_dir):
    """POST /api/report/full without auth token returns 401."""
    resp = client.post("/api/report/full", json={"confirm": True})
    assert resp.status_code == 401


def test_report_full_blocked_when_locked(client, state_dir, auth):
    """A locked engine returns a clean 423 instead of letting the agent tool loop
    raise SystemExit (which would not convert to a clean HTTP response)."""
    from state_manager import StateManager

    StateManager(db_path=str(state_dir / "engagement.db")).set_locked(True)
    resp = client.post("/api/report/full", headers=auth, json={"confirm": True})
    assert resp.status_code == 423


# ---------------------------------------------------------------------------
# Tier 3 — archive (packages engagement state + artifacts into a forensic zip).
# ReporterAgent.run() drives the agent tool loop (kill-switch → SystemExit), so
# the route mirrors report/full guards: token + confirm + require_unlocked, and
# 409 when there is no active engagement.
# ---------------------------------------------------------------------------

def test_archive_returns_metadata(client, state_dir, auth):
    """POST /api/archive with confirm=True packages the case and returns
    {engagement_id, archive_path, sha256}; the zip is written to disk."""
    import os
    from unittest.mock import AsyncMock, patch

    with patch("agents.reporter_agent.ReporterAgent.run", new=AsyncMock(return_value="# Case\nSummary.")):
        resp = client.post("/api/archive", headers=auth, json={"confirm": True})
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) >= {"engagement_id", "archive_path", "sha256"}
    assert len(body["sha256"]) == 64
    assert os.path.exists(body["archive_path"])


def test_archive_missing_confirm_returns_400(client, state_dir, auth):
    """POST /api/archive without confirm raises 400."""
    resp = client.post("/api/archive", headers=auth, json={})
    assert resp.status_code == 400


def test_archive_no_token_returns_401(client, state_dir):
    """POST /api/archive without auth token returns 401."""
    resp = client.post("/api/archive", json={"confirm": True})
    assert resp.status_code == 401


def test_archive_blocked_when_locked(client, state_dir, auth):
    """A locked engine returns a clean 423 instead of letting the agent tool loop
    raise SystemExit (which would not convert to a clean HTTP response)."""
    from state_manager import StateManager

    StateManager(db_path=str(state_dir / "engagement.db")).set_locked(True)
    resp = client.post("/api/archive", headers=auth, json={"confirm": True})
    assert resp.status_code == 423


# ---------------------------------------------------------------------------
# Tier 3 — model set (config-file mutation; no target, no agent loop, no
# kill-switch path, so token + confirm are the only guards)
# ---------------------------------------------------------------------------

@pytest.fixture
def model_config(tmp_path, monkeypatch):
    """Isolate ModelManager's config file to a temp path so these tests never
    clobber the real ~/.config/openelia/config.json."""
    import model_manager

    cfg_dir = tmp_path / "openelia_cfg"
    monkeypatch.setattr(model_manager, "_CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(model_manager, "_CONFIG_FILE", cfg_dir / "config.json")
    return cfg_dir


def test_model_set_local_updates_config(client, auth, model_config):
    """POST /api/model/set tier=local persists the local model and mode."""
    resp = client.post(
        "/api/model/set",
        headers=auth,
        json={"tier": "local", "model": "qwen3.5:2b", "confirm": True},
    )
    assert resp.status_code == 200
    cfg = resp.json()["config"]
    assert cfg["local_model"] == "qwen3.5:2b"
    assert cfg["mode"] == "local"


def test_model_set_cloud_updates_config(client, auth, model_config):
    """POST /api/model/set tier=cloud persists provider + model and mode."""
    resp = client.post(
        "/api/model/set",
        headers=auth,
        json={
            "tier": "cloud",
            "provider": "google",
            "model": "gemini-3.6-flash",
            "confirm": True,
        },
    )
    assert resp.status_code == 200
    cfg = resp.json()["config"]
    assert cfg["cloud_provider"] == "google"
    assert cfg["cloud_model"] == "gemini-3.6-flash"
    assert cfg["mode"] == "cloud"


def test_model_set_cloud_unknown_provider_returns_400(client, auth, model_config):
    """An unsupported cloud provider is rejected at the boundary (400)."""
    resp = client.post(
        "/api/model/set",
        headers=auth,
        json={"tier": "cloud", "provider": "bogusprovider", "model": "x", "confirm": True},
    )
    assert resp.status_code == 400


def test_model_set_cloud_missing_provider_returns_400(client, auth, model_config):
    """tier=cloud without a provider is a 400 (provider is required for cloud)."""
    resp = client.post(
        "/api/model/set",
        headers=auth,
        json={"tier": "cloud", "model": "x", "confirm": True},
    )
    assert resp.status_code == 400


def test_model_set_missing_confirm_returns_400(client, auth, model_config):
    """POST /api/model/set without confirm raises 400."""
    resp = client.post(
        "/api/model/set",
        headers=auth,
        json={"tier": "local", "model": "qwen3.5:2b"},
    )
    assert resp.status_code == 400


def test_model_set_no_token_returns_401(client, model_config):
    """POST /api/model/set without auth token returns 401."""
    resp = client.post(
        "/api/model/set",
        json={"tier": "local", "model": "qwen3.5:2b", "confirm": True},
    )
    assert resp.status_code == 401


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


# ---------------------------------------------------------------------------
# Tier 3 — grant (mints/revokes the signed IdP session authorizing red/purple).
# This route MINTS an offensive-authorization bearer credential, so it is the
# most sensitive Tier 3 surface: token + confirm gate it, and `role` is
# constrained to the allowlist so a caller cannot sign an arbitrary role into a
# valid session (credential injection). No agent loop → no require_unlocked;
# no target → no scope_gate (grant is what *creates* the scope authority).
# ---------------------------------------------------------------------------

def test_grant_mints_signed_session(client, state_dir, auth):
    """POST /api/grant with confirm=True writes a valid signed IdP session and
    returns {user, role, expires_epoch, idp_path}."""
    import json as _json

    from rbac_manager import verify_idp_session

    resp = client.post(
        "/api/grant",
        headers=auth,
        json={"user": "alice", "role": "red_team_lead", "ttl_hours": 1, "confirm": True},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"] == "alice" and body["role"] == "red_team_lead"
    session = _json.loads((state_dir / "idp_session.json").read_text())
    assert verify_idp_session(session) is True
    assert session["roles"] == ["red_team_lead"]


def test_grant_revoke_removes_session(client, state_dir, auth):
    """POST /api/grant revoke=True removes an existing session."""
    client.post(
        "/api/grant",
        headers=auth,
        json={"role": "admin", "confirm": True},
    )
    assert (state_dir / "idp_session.json").exists()

    resp = client.post("/api/grant", headers=auth, json={"revoke": True, "confirm": True})
    assert resp.status_code == 200
    assert resp.json()["revoked"] is True
    assert not (state_dir / "idp_session.json").exists()


def test_grant_unknown_role_rejected_at_boundary(client, state_dir, auth):
    """A role outside the allowlist is rejected before any session is signed."""
    resp = client.post(
        "/api/grant",
        headers=auth,
        json={"role": "superadmin", "confirm": True},
    )
    assert resp.status_code == 422  # Pydantic Literal rejects at the boundary
    assert not (state_dir / "idp_session.json").exists()


def test_grant_missing_confirm_returns_400(client, state_dir, auth):
    """POST /api/grant without confirm raises 400."""
    resp = client.post("/api/grant", headers=auth, json={"role": "admin"})
    assert resp.status_code == 400
    assert not (state_dir / "idp_session.json").exists()


def test_grant_no_token_returns_401(client, state_dir):
    """POST /api/grant without auth token returns 401."""
    resp = client.post("/api/grant", json={"role": "admin", "confirm": True})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tier 4 — nmap (sterile background scan). Dangerous op: it traverses the agent
# tool loop + kill-switch, so guards mirror /run/red exactly — token + confirm
# (400) + require_unlocked (423) + scope_gate (403). Target + args are validated
# at the boundary (400) BEFORE a background run launches, so a malformed or
# injection-laden command line never reaches the sterile executor.
# ---------------------------------------------------------------------------

def test_nmap_requires_confirm(client, state_dir, roe, auth):
    resp = client.post("/api/nmap", headers=auth, json={"target": "10.0.0.5"})
    assert resp.status_code == 400


def test_nmap_no_token_returns_401(client, state_dir, roe):
    resp = client.post("/api/nmap", json={"target": "10.0.0.5", "confirm": True})
    assert resp.status_code == 401


def test_nmap_out_of_scope_is_403(client, state_dir, roe, auth):
    resp = client.post("/api/nmap", headers=auth, json={"target": "8.8.8.8", "confirm": True})
    assert resp.status_code == 403


def test_nmap_blocked_when_locked(client, state_dir, roe, auth):
    from state_manager import StateManager

    StateManager(db_path=str(state_dir / "engagement.db")).set_locked(True)
    resp = client.post("/api/nmap", headers=auth, json={"target": "10.0.0.5", "confirm": True})
    assert resp.status_code == 423


def test_nmap_malformed_args_rejected_at_boundary(client, state_dir, roe, auth):
    """An in-scope target with a shell-metachar-laden --args string is a clean
    400 — never launched — so injection cannot reach the executor."""
    resp = client.post(
        "/api/nmap",
        headers=auth,
        json={"target": "10.0.0.5", "args": "-sV; rm -rf /", "confirm": True},
    )
    assert resp.status_code == 400


def test_nmap_in_scope_starts_background_run(client, state_dir, roe, auth, mock_invoke):
    resp = client.post(
        "/api/nmap",
        headers=auth,
        json={"target": "10.0.0.5", "args": "-sV", "confirm": True},
    )
    assert resp.status_code == 200
    rec = _wait_done(client, auth, resp.json()["run_id"])
    assert rec["status"] == "done"
    # The run is dispatched through the nmap branch of RunManager._invoke.
    assert mock_invoke.call_args.kwargs["tool"] == "nmap"
    assert mock_invoke.call_args.kwargs["nmap_args"] == "-sV"


def test_msf_requires_confirm(client, state_dir, roe, auth):
    resp = client.post("/api/msf", headers=auth, json={"target": "10.0.0.5"})
    assert resp.status_code == 400


def test_msf_no_token_returns_401(client, state_dir, roe):
    resp = client.post("/api/msf", json={"target": "10.0.0.5", "confirm": True})
    assert resp.status_code == 401


def test_msf_out_of_scope_is_403(client, state_dir, roe, auth):
    resp = client.post("/api/msf", headers=auth, json={"target": "8.8.8.8", "confirm": True})
    assert resp.status_code == 403


def test_msf_blocked_when_locked(client, state_dir, roe, auth):
    from state_manager import StateManager

    StateManager(db_path=str(state_dir / "engagement.db")).set_locked(True)
    resp = client.post("/api/msf", headers=auth, json={"target": "10.0.0.5", "confirm": True})
    assert resp.status_code == 423


def test_msf_malformed_target_rejected_at_boundary(client, state_dir, roe, auth):
    """A non-IP/CIDR target is a clean 400 — never launched — so a shell fragment
    masquerading as a target cannot reach the executor."""
    resp = client.post(
        "/api/msf",
        headers=auth,
        json={"target": "10.0.0.1; rm -rf /", "confirm": True},
    )
    assert resp.status_code == 400


def test_msf_in_scope_starts_background_run(client, state_dir, roe, auth, mock_invoke):
    resp = client.post(
        "/api/msf",
        headers=auth,
        json={"target": "10.0.0.5", "args": "show options", "confirm": True},
    )
    assert resp.status_code == 200
    rec = _wait_done(client, auth, resp.json()["run_id"])
    assert rec["status"] == "done"
    # The run is dispatched through the msf branch of RunManager._invoke.
    assert mock_invoke.call_args.kwargs["tool"] == "msf"
    assert mock_invoke.call_args.kwargs["msf_args"] == "show options"


def test_remediation_requires_confirm(client, state_dir, auth):
    resp = client.post("/api/execute-remediation", headers=auth, json={"action_id": 1})
    assert resp.status_code == 400


def test_remediation_no_token_returns_401(client, state_dir):
    resp = client.post("/api/execute-remediation", json={"action_id": 1, "confirm": True})
    assert resp.status_code == 401


def test_remediation_blocked_when_locked(client, state_dir, auth):
    from state_manager import StateManager

    StateManager(db_path=str(state_dir / "engagement.db")).set_locked(True)
    resp = client.post("/api/execute-remediation", headers=auth, json={"action_id": 1, "confirm": True})
    assert resp.status_code == 423


def test_remediation_invalid_action_id_rejected_at_boundary(client, state_dir, auth):
    """A non-positive action_id is a clean 400 — never launched. Blue op, so there
    is no target and no scope_gate; the boundary guard is the action_id instead."""
    resp = client.post("/api/execute-remediation", headers=auth, json={"action_id": 0, "confirm": True})
    assert resp.status_code == 400


def test_remediation_starts_background_run(client, state_dir, auth, mock_invoke):
    resp = client.post(
        "/api/execute-remediation",
        headers=auth,
        json={"action_id": 5, "confirm": True},
    )
    assert resp.status_code == 200
    rec = _wait_done(client, auth, resp.json()["run_id"])
    assert rec["status"] == "done"
    # The run is dispatched through the remediation branch of RunManager._invoke.
    assert mock_invoke.call_args.kwargs["tool"] == "remediation"
    assert mock_invoke.call_args.kwargs["action_id"] == 5
