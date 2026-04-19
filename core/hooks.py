# core/hooks.py — minimal stub (full implementation in Phase 2)
from core.schemas import AgentTask, AgentResult


def pre_run_hook(task: AgentTask) -> dict:
    return {"task_id": task.task_id, "agent_name": task.agent_name, "skills": []}


def post_run_hook(task: AgentTask, result: AgentResult, context: dict) -> None:
    context.clear()


def error_hook(task: AgentTask, exc: Exception, retry_count: int, max_retries: int) -> None:
    pass
