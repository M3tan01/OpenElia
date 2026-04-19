"""
core/hooks.py — Agent lifecycle hooks for the AsyncWorkerPool.

Called by orchestrator._dispatch_task to manage context injection and cleanup.
All hooks are synchronous — they must not perform LLM calls.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.schemas import AgentResult, AgentTask, ErrorPayload

_STATE_DIR = Path(os.getenv("STATE_DIR", "state"))


def pre_run_hook(task: AgentTask) -> dict:
    """
    Inject the minimal JIT context required by this specific agent.

    Returns a mutable context dict passed to the agent and later
    cleared by post_run_hook. Only lightweight metadata — no agent instances.
    """
    from jit_loader import JITLoader
    loader = JITLoader()
    skill_names = loader.get_skills_for_agent(task.agent_name)
    return {
        "skills": skill_names,
        "task_id": task.task_id,
        "agent_name": task.agent_name,
    }


def post_run_hook(task: AgentTask, result: AgentResult, context: dict) -> None:
    """
    Persist the result to state/task_results.jsonl and free the agent context.
    """
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "task_id": result.task_id,
        "agent_name": result.agent_name,
        "status": result.status,
        "output_keys": list(result.output.keys()),
        "completed_at": result.completed_at,
        "tokens_used": result.tokens_used,
    }
    results_log = _STATE_DIR / "task_results.jsonl"
    with results_log.open("a") as fh:
        fh.write(json.dumps(record) + "\n")

    context.clear()


def error_hook(
    task: AgentTask,
    exc: Exception,
    retry_count: int,
    max_retries: int,
) -> None:
    """
    Log a structured ErrorPayload to state/audit.log.
    Does NOT raise — pool decides retry logic based on retry_count.
    """
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    payload = ErrorPayload(
        task_id=task.task_id,
        agent_name=task.agent_name,
        error=str(exc),
        retry_count=retry_count,
        will_retry=retry_count < max_retries,
    )
    audit_log = _STATE_DIR / "audit.log"
    with audit_log.open("a") as fh:
        fh.write(payload.model_dump_json() + "\n")
