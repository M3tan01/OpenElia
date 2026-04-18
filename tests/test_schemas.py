import pytest
from pydantic import ValidationError
from core.schemas import AgentTask, AgentResult, RoutingDecision, ErrorPayload, AgentTier, Domain


def test_agent_task_auto_generates_id_and_timestamp():
    task = AgentTask(
        domain=Domain.RED,
        tier=AgentTier.RECON,
        agent_name="pentester_recon",
        payload={"target": "10.0.0.1"},
    )
    assert len(task.task_id) == 36  # UUID4 format
    assert task.retry_count == 0
    assert "T" in task.created_at  # ISO-8601


def test_agent_task_model_dump_is_json_serializable():
    import json
    task = AgentTask(
        domain=Domain.BLUE,
        tier=AgentTier.ANALYSIS,
        agent_name="defender_ana",
        payload={"log": "auth failure"},
    )
    data = task.model_dump()
    serialized = json.dumps(data)  # must not raise
    assert '"blue"' in serialized
    assert '"analysis"' in serialized


def test_agent_result_fields():
    result = AgentResult(
        task_id="abc-123",
        agent_name="test_agent",
        status="success",
        output={"finding": "open port 22"},
    )
    assert result.status == "success"
    assert result.tokens_used == 0


def test_routing_decision_empty_tasks_by_default():
    rd = RoutingDecision(domain=Domain.REPORTER, confidence=0.95, reason="report requested")
    assert rd.tasks == []


def test_error_payload_structure():
    ep = ErrorPayload(
        task_id="xyz",
        agent_name="bad_agent",
        error="connection refused",
        retry_count=2,
        will_retry=True,
    )
    assert ep.will_retry is True
    assert ep.retry_count == 2


def test_agent_tier_ordering():
    assert AgentTier.RECON < AgentTier.ANALYSIS < AgentTier.EXECUTION


def test_agent_task_invalid_domain_raises():
    with pytest.raises(Exception):
        AgentTask(domain="unknown_domain", tier=AgentTier.RECON, agent_name="x", payload={})


def test_agent_task_is_frozen():
    task = AgentTask(domain=Domain.RED, tier=AgentTier.RECON, agent_name="x", payload={})
    with pytest.raises(ValidationError):
        task.retry_count = 1  # frozen model must reject mutation


def test_agent_task_model_copy_for_retry():
    task = AgentTask(domain=Domain.RED, tier=AgentTier.RECON, agent_name="x", payload={})
    retried = task.model_copy(update={"retry_count": 1})
    assert retried.retry_count == 1
    assert task.task_id == retried.task_id  # same task, new attempt
    assert task.retry_count == 0  # original unchanged


def test_agent_task_json_round_trip():
    import json
    original = AgentTask(domain=Domain.RED, tier=AgentTier.RECON, agent_name="x", payload={"target": "1.2.3.4"})
    data = json.loads(json.dumps(original.model_dump()))
    restored = AgentTask.model_validate(data)
    assert restored.task_id == original.task_id
    assert restored.tier == AgentTier.RECON


def test_agent_tier_enum_has_exactly_three_members():
    """Ensures _order (or similar) is not accidentally an enum member."""
    members = list(AgentTier)
    assert len(members) == 3
    assert set(m.value for m in members) == {"recon", "analysis", "execution"}


def test_agent_result_invalid_status_raises():
    with pytest.raises(ValidationError):
        AgentResult(task_id="x", agent_name="y", status="invalid_status", output={})
