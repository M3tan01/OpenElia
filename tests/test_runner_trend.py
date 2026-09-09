import pytest
from webdash.runner import RunManager


@pytest.mark.asyncio
async def test_purple_run_snapshots_on_completion(tmp_path, monkeypatch):
    state_dir = tmp_path
    captured = {}

    async def fake_invoke(self, **kw):
        # Simulate the engine: create a campaign-tagged engagement + a caught TTP.
        from state_manager import StateManager
        from datetime import datetime, timezone
        sm = StateManager(db_path=str(state_dir / "engagement.db"))
        eng = sm.initialize_engagement("10.0.0.1", "web", campaign_id=kw.get("campaign_id"))
        eid = eng["engagement"]["id"]
        now = datetime.now(timezone.utc).isoformat()
        with sm._get_conn() as conn:
            conn.execute("INSERT INTO findings (engagement_id, title, severity, mitre_ttp, timestamp) "
                         "VALUES (?,?,?,?,?)", (eid, "t", "high", "T1003", now))
            conn.execute("INSERT INTO blue_alerts (engagement_id, type, mitre_ttp, escalated, timestamp) "
                         "VALUES (?,?,?,?,?)", (eid, "ids", "T1003", 0, now))
            conn.commit()
        sm.set_metadata("blue_run_status", "complete", eid)
        captured["eid"] = eid
        return {"ok": True}

    monkeypatch.setattr(RunManager, "_invoke", fake_invoke)

    rm = RunManager()
    run_id = await rm.start(domain="purple", task="t", targets=["10.0.0.1"],
                            state_dir=str(state_dir), campaign_id="C1")
    # Wait for the background task to finish.
    import asyncio
    for _ in range(200):
        if rm._runs[run_id]["status"] in ("done", "error", "cancelled"):
            break
        await asyncio.sleep(0.01)

    from state_manager import StateManager
    sm = StateManager(db_path=str(state_dir / "engagement.db"))
    trend = sm.get_campaign_trend("C1")
    assert len(trend) == 1
    assert trend[0]["coverage_pct"] == 100.0


@pytest.mark.asyncio
async def test_non_purple_run_does_not_snapshot(tmp_path, monkeypatch):
    async def fake_invoke(self, **kw):
        from state_manager import StateManager
        sm = StateManager(db_path=str(tmp_path / "engagement.db"))
        sm.initialize_engagement("10.0.0.1", "web", campaign_id=kw.get("campaign_id"))
        return {"ok": True}
    monkeypatch.setattr(RunManager, "_invoke", fake_invoke)

    rm = RunManager()
    run_id = await rm.start(domain="red", task="t", targets=["10.0.0.1"],
                            state_dir=str(tmp_path), campaign_id="C1")
    import asyncio
    for _ in range(200):
        if rm._runs[run_id]["status"] in ("done", "error", "cancelled"):
            break
        await asyncio.sleep(0.01)

    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    assert sm.get_campaign_trend("C1") == []  # red-only never snapshots
