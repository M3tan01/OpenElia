#!/usr/bin/env python3
"""
demo_parallel.py — Phase 4 proof: 3 agents, 0 shared context, fully parallel.

Run with:
    python demo_parallel.py

Expected output: all three agents complete in ~1 sleep cycle (0.1s), not 0.3s.
"""

import asyncio
import time
from core.schemas import AgentTask, AgentResult, AgentTier, Domain
from core.worker_pool import AsyncWorkerPool


async def dummy_handler(task: AgentTask) -> AgentResult:
    """
    Simulates an isolated agent run.
    Each agent gets its own local context dict — nothing is shared.
    """
    local_context = {
        "agent": task.agent_name,
        "payload": task.payload,
        # In production: pre_run_hook(task) would populate skills here.
    }
    print(f"[{task.agent_name}] START  tier={task.tier.name}  ctx_id={id(local_context)}")
    await asyncio.sleep(0.1)  # simulate LLM call latency
    print(f"[{task.agent_name}] FINISH tier={task.tier.name}")
    local_context.clear()  # simulate post_run_hook freeing context
    return AgentResult(
        task_id=task.task_id,
        agent_name=task.agent_name,
        status="success",
        output={"tier": task.tier.name},
    )


async def main() -> None:
    pool = AsyncWorkerPool(workers_per_tier=3)

    tasks = [
        AgentTask(domain=Domain.RED, tier=AgentTier.RECON,     agent_name="recon_agent",     payload={"target": "10.0.0.1"}),
        AgentTask(domain=Domain.RED, tier=AgentTier.ANALYSIS,  agent_name="analysis_agent",  payload={"target": "10.0.0.1"}),
        AgentTask(domain=Domain.RED, tier=AgentTier.EXECUTION, agent_name="execution_agent", payload={"target": "10.0.0.1"}),
    ]

    for t in tasks:
        await pool.submit(t)

    print("\n[Demo] Launching 3 agents across 3 tiers...\n")
    start = time.monotonic()
    results = await pool.run_until_complete(dummy_handler)
    elapsed = time.monotonic() - start

    print(f"\n[Demo] All agents complete in {elapsed:.3f}s")
    for r in sorted(results, key=lambda r: r.agent_name):
        print(f"  ✓ {r.agent_name}: {r.status} | output={r.output}")

    assert elapsed < 0.25, f"FAIL: agents ran serially ({elapsed:.3f}s)"
    print("\n[Demo] PASS — agents ran concurrently, no shared context.")


if __name__ == "__main__":
    asyncio.run(main())
