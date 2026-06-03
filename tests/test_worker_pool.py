"""
Tests for AsyncWorkerPool.

Uses pytest-asyncio with auto mode so coroutines run without explicit event loop setup.
"""
import asyncio
import pytest
from core.schemas import AgentTask, AgentResult, AgentTier, Domain
from core.worker_pool import AsyncWorkerPool, MAX_RETRIES

pytestmark = pytest.mark.asyncio


async def _ok_handler(task: AgentTask) -> AgentResult:
    """Succeeds immediately."""
    await asyncio.sleep(0)  # yield control to prove concurrency
    return AgentResult(
        task_id=task.task_id,
        agent_name=task.agent_name,
        status="success",
        output={"done": True},
    )


async def test_single_task_completes():
    pool = AsyncWorkerPool(workers_per_tier=1)
    task = AgentTask(domain=Domain.RED, tier=AgentTier.RECON, agent_name="t1", payload={})
    await pool.submit(task)
    results = await pool.run_until_complete(_ok_handler)
    assert len(results) == 1
    assert results[0].status == "success"
    assert results[0].task_id == task.task_id


async def test_six_tasks_across_two_tiers_all_complete():
    pool = AsyncWorkerPool(workers_per_tier=3)
    for _ in range(3):
        await pool.submit(AgentTask(domain=Domain.RED, tier=AgentTier.RECON, agent_name="recon", payload={}))
    for _ in range(3):
        await pool.submit(AgentTask(domain=Domain.BLUE, tier=AgentTier.ANALYSIS, agent_name="ana", payload={}))
    results = await pool.run_until_complete(_ok_handler)
    assert len(results) == 6
    assert all(r.status == "success" for r in results)


async def test_failed_task_retries_exactly_max_retries_times():
    call_log: list[str] = []

    async def _fail_handler(task: AgentTask) -> AgentResult:
        call_log.append(task.task_id)
        raise RuntimeError("deliberate")

    pool = AsyncWorkerPool(workers_per_tier=1)
    task = AgentTask(domain=Domain.RED, tier=AgentTier.RECON, agent_name="bad", payload={})
    await pool.submit(task)
    results = await pool.run_until_complete(_fail_handler)
    assert results[0].status == "error"
    # 1 initial attempt + MAX_RETRIES retries
    assert len(call_log) == MAX_RETRIES + 1


async def test_tasks_run_concurrently_within_same_tier():
    """Three tasks in Tier-1 with 3 workers should finish in ~1 sleep cycle, not 3."""
    import time

    async def _slow_handler(task: AgentTask) -> AgentResult:
        await asyncio.sleep(0.05)
        return AgentResult(task_id=task.task_id, agent_name=task.agent_name, status="success", output={})

    pool = AsyncWorkerPool(workers_per_tier=3)
    for _ in range(3):
        await pool.submit(AgentTask(domain=Domain.RED, tier=AgentTier.RECON, agent_name="s", payload={}))

    start = time.monotonic()
    results = await pool.run_until_complete(_slow_handler)
    elapsed = time.monotonic() - start

    assert len(results) == 3
    assert elapsed < 0.15, f"Tasks ran serially (elapsed={elapsed:.2f}s) — concurrency broken"


async def test_higher_priority_drains_first_within_tier():
    """With one worker on a tier, the highest-priority task runs first regardless
    of arrival order."""
    order: list[str] = []

    async def _rec(task: AgentTask) -> AgentResult:
        order.append(task.agent_name)
        return AgentResult(task_id=task.task_id, agent_name=task.agent_name,
                           status="success", output={})

    pool = AsyncWorkerPool(workers_per_tier=1)
    # Arrival order low, high, mid → expected drain order high, mid, low.
    await pool.submit(AgentTask(domain=Domain.RED, tier=AgentTier.RECON, agent_name="low", payload={}, priority=0.1))
    await pool.submit(AgentTask(domain=Domain.RED, tier=AgentTier.RECON, agent_name="high", payload={}, priority=0.9))
    await pool.submit(AgentTask(domain=Domain.RED, tier=AgentTier.RECON, agent_name="mid", payload={}, priority=0.5))
    await pool.run_until_complete(_rec)
    assert order == ["high", "mid", "low"]


async def test_equal_priority_preserves_fifo():
    """Equal priorities fall back to FIFO via the monotonic seq tiebreak."""
    order: list[str] = []

    async def _rec(task: AgentTask) -> AgentResult:
        order.append(task.agent_name)
        return AgentResult(task_id=task.task_id, agent_name=task.agent_name,
                           status="success", output={})

    pool = AsyncWorkerPool(workers_per_tier=1)
    for n in ("a", "b", "c"):
        await pool.submit(AgentTask(domain=Domain.RED, tier=AgentTier.RECON, agent_name=n, payload={}, priority=0.5))
    await pool.run_until_complete(_rec)
    assert order == ["a", "b", "c"]
