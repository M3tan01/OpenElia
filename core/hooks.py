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
from core.audit_chain import append as _audit_append

def _state_dir() -> Path:
    return Path(os.getenv("STATE_DIR", "state"))


def pre_run_hook(task: AgentTask) -> dict:
    """
    Build the lifecycle context dict for this task (telemetry only).

    NOTE: the ``skills`` list here is for logging/observability. The actual
    skill *injection* into the agent's system prompt happens inside
    BaseAgent._build_system_prompt (via JITLoader.load_semantic_skills) when the
    agent runs — this hook does not feed skills into the agent. JITLoader's
    discovery scan is memoized, so computing the list here is cheap.

    Returns a mutable context dict later cleared by post_run_hook. Only
    lightweight metadata — no agent instances.
    """
    from jit_loader import JITLoader
    loader = JITLoader()
    skill_names = loader.get_skills_for_agent(task.agent_name)
    _write_running(task)
    return {
        "skills": skill_names,
        "task_id": task.task_id,
        "agent_name": task.agent_name,
    }


def _write_running(task: AgentTask) -> None:
    """Append an in-progress marker so the dashboard shows an agent the moment it
    starts — not only when it finishes.

    Written to task_results.jsonl (tailed by the live WS stream) but deliberately
    NOT to the immutable audit chain: 'running' is not a completion fact. The
    `completed_at` is null so webdash.data.tasks() (which scopes by completed_at)
    ignores it; the terminal record from post_run_hook then supersedes it live
    (dedup is by task_id, latest status wins). Best-effort — a telemetry write
    failure must never block the agent from running, so every failure mode is
    swallowed here: not only disk/OSError, but a non-numeric `priority`
    (round() -> TypeError) or a non-serializable field. Telemetry never
    propagates into the agent's run path.
    """
    try:
        state_dir = _state_dir()
        state_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "task_id": task.task_id,
            "agent_name": task.agent_name,
            "status": "running",
            "output_keys": [],
            "completed_at": None,
            "tokens_used": 0,
            "priority": round(getattr(task, "priority", 0.0), 4),
        }
        with (state_dir / "task_results.jsonl").open("a") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass


def post_run_hook(task: AgentTask, result: AgentResult, context: dict) -> None:
    """
    Persist the result to state/task_results.jsonl and free the agent context.
    """
    state_dir = _state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "task_id": result.task_id,
        "agent_name": result.agent_name,
        "status": result.status,
        "output_keys": list(result.output.keys()),
        "completed_at": result.completed_at,
        "tokens_used": result.tokens_used,
        "priority": round(getattr(task, "priority", 0.0), 4),
    }
    results_log = state_dir / "task_results.jsonl"
    try:
        with results_log.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
        _audit_append(state_dir / "audit.log", record)
    finally:
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
    state_dir = _state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    payload = ErrorPayload(
        task_id=task.task_id,
        agent_name=task.agent_name,
        error=str(exc),
        retry_count=retry_count,
        will_retry=retry_count < max_retries,
    )
    audit_log = state_dir / "audit.log"
    _audit_append(audit_log, payload.model_dump())
