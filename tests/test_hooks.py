import json
import pytest
from core.schemas import AgentTask, AgentResult, AgentTier, Domain
from core.hooks import pre_run_hook, post_run_hook, error_hook


def _make_task(**kwargs) -> AgentTask:
    defaults = dict(domain=Domain.RED, tier=AgentTier.RECON, agent_name="test_agent", payload={"target": "1.2.3.4"})
    return AgentTask(**{**defaults, **kwargs})


def test_pre_run_hook_returns_context_with_skills():
    task = _make_task(agent_name="pentester_recon")
    ctx = pre_run_hook(task)
    assert "skills" in ctx
    assert "task_id" in ctx
    assert "agent_name" in ctx
    assert isinstance(ctx["skills"], list)
    assert ctx["task_id"] == task.task_id
    assert ctx["agent_name"] == task.agent_name


def test_post_run_hook_clears_context(tmp_path, monkeypatch):
    monkeypatch.setenv("STATE_DIR", str(tmp_path))
    task = _make_task()
    result = AgentResult(task_id=task.task_id, agent_name="test_agent", status="success", output={"finding": "x"})
    ctx = {"skills": ["nmap"], "state": "running"}
    post_run_hook(task, result, ctx)
    assert ctx == {}


def test_post_run_hook_writes_jsonl(tmp_path, monkeypatch):
    monkeypatch.setenv("STATE_DIR", str(tmp_path))
    task = _make_task()
    result = AgentResult(task_id=task.task_id, agent_name="test_agent", status="success", output={"port": 22})
    ctx = {}
    post_run_hook(task, result, ctx)

    log_path = tmp_path / "task_results.jsonl"
    assert log_path.exists()
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["task_id"] == task.task_id
    assert record["status"] == "success"
    assert "port" in record["output_keys"]


def test_error_hook_writes_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("STATE_DIR", str(tmp_path))
    task = _make_task()
    error_hook(task, RuntimeError("test error"), retry_count=1, max_retries=3)

    log_path = tmp_path / "audit.log"
    assert log_path.exists()
    payload = json.loads(log_path.read_text().strip())
    assert payload["will_retry"] is True
    assert payload["retry_count"] == 1
    assert "test error" in payload["error"]


def test_error_hook_sets_will_retry_false_at_max(tmp_path, monkeypatch):
    monkeypatch.setenv("STATE_DIR", str(tmp_path))
    task = _make_task()
    error_hook(task, RuntimeError("final"), retry_count=3, max_retries=3)

    log_path = tmp_path / "audit.log"
    payload = json.loads(log_path.read_text().strip())
    assert payload["will_retry"] is False


def test_jit_loader_get_skills_for_agent_returns_list():
    from jit_loader import JITLoader
    loader = JITLoader()
    result = loader.get_skills_for_agent("pentester_recon")
    assert isinstance(result, list)


def test_jit_loader_unknown_agent_returns_empty():
    from jit_loader import JITLoader
    loader = JITLoader()
    result = loader.get_skills_for_agent("nonexistent_agent_xyz")
    assert result == []
