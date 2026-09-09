"""
Tests for GET /api/campaign/{campaign_id}/trend and its data-layer wrapper
DashboardData.campaign_trend(). Follows the fixture pattern in
tests/test_webdash_monitor.py (conftest_webdash.client/auth/state_dir).
"""
from __future__ import annotations

from datetime import datetime, timezone

from webdash.data import DashboardData

from tests.conftest_webdash import auth, client, state_dir, token  # noqa: F401


def test_campaign_trend_data_method(tmp_path):
    from state_manager import StateManager

    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "auth", campaign_id="C1")
    eid = eng["engagement"]["id"]
    now = datetime.now(timezone.utc).isoformat()
    with sm._get_conn() as conn:
        conn.execute(
            "INSERT INTO findings (engagement_id, title, severity, mitre_ttp, timestamp) "
            "VALUES (?,?,?,?,?)",
            (eid, "t", "high", "T1003", now),
        )
        conn.execute(
            "INSERT INTO blue_alerts (engagement_id, type, mitre_ttp, escalated, timestamp) "
            "VALUES (?,?,?,?,?)",
            (eid, "ids", "T1003", 0, now),
        )
        conn.commit()
    sm.set_metadata("blue_run_status", "complete", eid)
    sm.record_coverage_snapshot(eid)

    data = DashboardData(state_dir=str(tmp_path))
    resp = data.campaign_trend("C1")
    assert resp["campaign_id"] == "C1"
    assert len(resp["snapshots"]) == 1
    assert resp["snapshots"][0]["coverage_pct"] == 100.0
    # Snapshot shape passed through unchanged (locked contract).
    assert set(resp["snapshots"][0]) == {"ts", "coverage_pct", "rung_counts", "ttps"}


def test_campaign_trend_unknown_is_empty(tmp_path):
    data = DashboardData(state_dir=str(tmp_path))
    assert data.campaign_trend("nope") == {"campaign_id": "nope", "snapshots": []}


def test_campaign_trend_route_requires_token(client, state_dir):
    """No token → 401, matching sibling monitor routes."""
    resp = client.get("/api/campaign/C1/trend")
    assert resp.status_code == 401


def test_campaign_trend_route_unknown_campaign_returns_empty(client, state_dir, auth):
    """Unknown campaign_id → 200 with empty snapshots (not 404)."""
    resp = client.get("/api/campaign/does-not-exist/trend", headers=auth)
    assert resp.status_code == 200
    assert resp.json() == {"campaign_id": "does-not-exist", "snapshots": []}


def test_campaign_trend_route_returns_wrapper(client, auth, tmp_path, monkeypatch):
    """Seeded campaign snapshot → route returns {campaign_id, snapshots} with
    the snapshot passed through unchanged."""
    monkeypatch.setenv("OPENELIA_STATE_DIR", str(tmp_path))

    from state_manager import StateManager

    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    eng = sm.initialize_engagement("10.0.0.1", "auth", campaign_id="C1")
    eid = eng["engagement"]["id"]
    now = datetime.now(timezone.utc).isoformat()
    with sm._get_conn() as conn:
        conn.execute(
            "INSERT INTO findings (engagement_id, title, severity, mitre_ttp, timestamp) "
            "VALUES (?,?,?,?,?)",
            (eid, "t", "high", "T1003", now),
        )
        conn.execute(
            "INSERT INTO blue_alerts (engagement_id, type, mitre_ttp, escalated, timestamp) "
            "VALUES (?,?,?,?,?)",
            (eid, "ids", "T1003", 0, now),
        )
        conn.commit()
    sm.set_metadata("blue_run_status", "complete", eid)
    sm.record_coverage_snapshot(eid)

    resp = client.get("/api/campaign/C1/trend", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert body["campaign_id"] == "C1"
    assert len(body["snapshots"]) == 1
    assert body["snapshots"][0]["coverage_pct"] == 100.0
