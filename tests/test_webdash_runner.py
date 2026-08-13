"""RunManager unit tests — task retention + cancellation status."""
from __future__ import annotations

import asyncio

import pytest

pytestmark = pytest.mark.asyncio


async def test_completed_run_marked_done():
    from webdash.runner import RunManager

    rm = RunManager()
    rm._invoke = lambda *a, **kw: _done()  # type: ignore[assignment]

    async def _done():
        return {"domain": "red"}

    rid = await rm.start(domain="red", task="t", targets=["10.0.0.1"], state_dir="state")
    await asyncio.gather(*rm._tasks)
    assert rm.get(rid)["status"] == "done"
    assert rm.active() is None  # cleared after completion


async def test_cancelled_run_marked_cancelled():
    from webdash.runner import RunManager

    rm = RunManager()

    async def _hang(*a, **kw):
        await asyncio.sleep(10)

    rm._invoke = _hang  # type: ignore[assignment]
    rid = await rm.start(domain="red", task="t", targets=["10.0.0.1"], state_dir="state")
    task = next(iter(rm._tasks))
    await asyncio.sleep(0)  # let it enter the sleep
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert rm.get(rid)["status"] == "cancelled"  # not stuck on "running"
    assert rm.active() is None


def _seed_coverage(tmp_path, *, caught: bool, blue_done: bool):
    """Seed a tmp engagement: one red finding on T1003; optionally a matching blue
    alert and a completed blue run. Returns the state_dir path (str)."""
    from state_manager import StateManager

    sm = StateManager(db_path=str(tmp_path / "engagement.db"))
    sm.initialize_engagement("10.0.0.5", "purple engagement")
    sm.add_finding(
        severity="high", title="LSASS dump", description="d", evidence="e",
        mitre_ttp="T1003.001", source_agent="pentester_ex",
    )
    if caught:
        sm.add_blue_alert(
            alert_type="cred-access", description="d", severity="high",
            source="defender_mon", mitre_ttp="T1003",
        )
    if blue_done:
        sm.set_metadata("blue_run_status", "complete")
    return str(tmp_path)


class _CaptureClient:
    """Stand-in httpx.AsyncClient that records the JSON payload of the POST."""
    def __init__(self, sink: dict):
        self._sink = sink

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json, timeout):
        self._sink["url"] = url
        self._sink["payload"] = json

        class _Resp:
            def raise_for_status(self_inner):
                return None

        return _Resp()


def _purple_rec(state_dir: str) -> dict:
    return {
        "run_id": "abc123",
        "domain": "purple",
        "task": "purple sweep",
        "targets": ["10.0.0.5"],
        "status": "done",
        "started": "t0",
        "finished": "t1",
        "result": {"ok": True},
        "error": None,
        "callback_url": "https://n8n.local/webhook/x",
        "state_dir": state_dir,
    }


async def test_notify_purple_enriches_with_coverage(tmp_path, monkeypatch):
    import httpx

    import core.webhook
    from webdash.runner import RunManager

    state_dir = _seed_coverage(tmp_path, caught=True, blue_done=True)
    monkeypatch.setattr(core.webhook, "validate_webhook_url", lambda url, key: None)
    sink: dict = {}
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **kw: _CaptureClient(sink))

    await RunManager()._notify(_purple_rec(state_dir))

    payload = sink["payload"]
    assert payload["coverage_pct"] == 100.0
    assert payload["caught_ttps"] == ["T1003"]
    assert payload["missed_ttps"] == []


async def test_notify_non_purple_omits_coverage(tmp_path, monkeypatch):
    import httpx

    import core.webhook
    from webdash.runner import RunManager

    state_dir = _seed_coverage(tmp_path, caught=True, blue_done=True)
    monkeypatch.setattr(core.webhook, "validate_webhook_url", lambda url, key: None)
    sink: dict = {}
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **kw: _CaptureClient(sink))

    rec = _purple_rec(state_dir)
    rec["domain"] = "red"
    await RunManager()._notify(rec)

    payload = sink["payload"]
    assert "coverage_pct" not in payload
    assert "caught_ttps" not in payload
