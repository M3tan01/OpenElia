"""
core/worker_pool.py — Tier-stratified async worker pool.

Design:
  - Three independent asyncio.Queue instances, one per AgentTier.
  - N worker coroutines per tier run concurrently (default=3 to avoid LLM thrashing).
  - Failed tasks are re-enqueued up to MAX_RETRIES times, then marked "error".
  - The pool is single-use: call run_until_complete() once, then discard.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from core.schemas import AgentResult, AgentTask, AgentTier

log = logging.getLogger(__name__)

MAX_RETRIES: int = 3


class AsyncWorkerPool:
    """
    Stateless async worker pool with one queue per execution tier.

    Usage:
        pool = AsyncWorkerPool()
        await pool.submit(task)
        results = await pool.run_until_complete(handler)
    """

    def __init__(self, workers_per_tier: int = 3) -> None:
        self._queues: dict[AgentTier, asyncio.Queue[AgentTask]] = {
            tier: asyncio.Queue() for tier in AgentTier
        }
        self._results: list[AgentResult] = []
        self._workers_per_tier = workers_per_tier

    async def submit(self, task: AgentTask) -> None:
        """Enqueue a task into its tier queue. Non-blocking."""
        await self._queues[task.tier].put(task)

    async def run_until_complete(
        self,
        handler: Callable[[AgentTask], Awaitable[AgentResult]],
    ) -> list[AgentResult]:
        """
        Drain all tier queues using concurrent workers.

        Args:
            handler: Async callable that executes a single AgentTask
                     and returns an AgentResult. Raised exceptions trigger retry.

        Returns:
            List of AgentResult objects (success or final error) in completion order.
        """
        stop_event = asyncio.Event()
        worker_tasks: list[asyncio.Task] = []

        for tier in AgentTier:
            for _ in range(self._workers_per_tier):
                t = asyncio.create_task(
                    self._worker(tier, handler, stop_event),
                    name=f"worker-{tier.name}-{_}",
                )
                worker_tasks.append(t)

        # Block until all queues are drained
        for queue in self._queues.values():
            await queue.join()

        stop_event.set()
        await asyncio.gather(*worker_tasks, return_exceptions=True)

        return list(self._results)

    async def _worker(
        self,
        tier: AgentTier,
        handler: Callable[[AgentTask], Awaitable[AgentResult]],
        stop: asyncio.Event,
    ) -> None:
        queue = self._queues[tier]
        while not stop.is_set():
            try:
                task = queue.get_nowait()
            except asyncio.QueueEmpty:
                await asyncio.sleep(0)  # yield — recheck stop or new items
                continue

            try:
                result = await handler(task)
                self._results.append(result)
            except Exception as exc:
                log.warning("[WorkerPool] Task %s failed: %s", task.task_id, exc)
                if task.retry_count < MAX_RETRIES:
                    retried = task.model_copy(update={"retry_count": task.retry_count + 1})
                    await queue.put(retried)
                else:
                    self._results.append(
                        AgentResult(
                            task_id=task.task_id,
                            agent_name=task.agent_name,
                            status="error",
                            output={},
                            error_detail=str(exc),
                        )
                    )
            finally:
                queue.task_done()
