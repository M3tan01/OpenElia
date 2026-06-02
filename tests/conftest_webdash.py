"""
Shared fixtures for webdash tests. Imported via `from tests.conftest_webdash import *`
in each webdash test module (kept out of the global conftest to avoid touching
unrelated suites).
"""
from __future__ import annotations

import json

import pytest

TEST_TOKEN = "test-token-abc123"


@pytest.fixture
def token(monkeypatch):
    """Force a known dashboard token without touching the OS keychain."""
    monkeypatch.setattr("webdash.security.current_token", lambda: TEST_TOKEN)
    return TEST_TOKEN


@pytest.fixture
def auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    """Seed an isolated state directory and point the API at it."""
    monkeypatch.setenv("OPENELIA_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("MAX_TOKEN_BUDGET", "5.00")

    from state_manager import StateManager

    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    sm.initialize_engagement("10.0.0.5", "test scope")
    sm.add_finding("high", "Test finding", "desc", "evidence", "T1059")
    # The active-engagement start bounds which task results the dashboard shows.
    started = sm.read()["engagement"]["started"]

    from security_manager import AuditLogger

    AuditLogger(log_path=str(tmp_path / "audit.log")).log_event(
        "pentester_recon", "10.0.0.5", "scan started", "LLM_CALL", "unit-test"
    )

    (tmp_path / "task_results.jsonl").write_text(
        json.dumps(
            {
                "task_id": "t1",
                "agent_name": "pentester_recon",
                "status": "success",
                "completed_at": started,  # within the active engagement window
                "tokens_used": 10,
            }
        )
        + "\n"
    )

    from graph_manager import GraphManager

    gm = GraphManager(db_path=str(tmp_path / "attack_surface.json"))
    gm.add_host("10.0.0.5", hostname="target")
    gm.add_service("10.0.0.5", 80, "tcp", "http")

    (tmp_path / "costs.json").write_text(
        json.dumps({"20260601_0000": {"total_cost": 0.5, "calls": 3}})
    )

    return tmp_path


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from webdash.server import app

    return TestClient(app)
