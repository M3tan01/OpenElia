"""RunManager unit tests — task retention + cancellation status."""
from __future__ import annotations

import asyncio

import pytest

pytestmark = pytest.mark.asyncio


async def test_completed_run_marked_done():
    from webdash.runner import RunManager

    rm = RunManager()
    rm._invoke = lambda *a: _done()  # type: ignore[assignment]

    async def _done():
        return {"domain": "red"}

    rid = await rm.start(domain="red", task="t", targets=["10.0.0.1"], state_dir="state")
    await asyncio.gather(*rm._tasks)
    assert rm.get(rid)["status"] == "done"
    assert rm.active() is None  # cleared after completion


async def test_cancelled_run_marked_cancelled():
    from webdash.runner import RunManager

    rm = RunManager()

    async def _hang(*a):
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
