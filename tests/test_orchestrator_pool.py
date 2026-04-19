"""
tests/test_orchestrator_pool.py — AsyncWorkerPool dispatch integration tests.

Validates that Orchestrator.route() enqueues typed AgentTask objects into the
pool rather than calling agent constructors directly.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from core.schemas import AgentTask, AgentResult, AgentTier, Domain

pytestmark = pytest.mark.asyncio


async def test_orchestrator_route_enqueues_red_tasks(tmp_path):
    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("10.0.0.1", "single-host")

    from orchestrator import Orchestrator
    orch = Orchestrator(sm)

    enqueued: list[AgentTask] = []

    async def fake_submit(task: AgentTask):
        enqueued.append(task)

    with patch.object(orch, "_classify", new=AsyncMock(return_value={"domain": "red", "confidence": 0.9, "reason": "test"})), \
         patch("orchestrator.RBACManager") as mock_rbac, \
         patch("orchestrator.AsyncWorkerPool") as mock_pool_class:
        mock_rbac.enforce_red_team_auth.return_value = True
        # Replace pool with a mock that captures submissions
        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock(side_effect=lambda task: enqueued.append(task))
        mock_pool.run_until_complete = AsyncMock(return_value=[
            AgentResult(task_id="x", agent_name="pentester_recon", status="success", output={})
        ])
        mock_pool_class.return_value = mock_pool
        await orch.route("scan target", targets=["10.0.0.1"])

    assert len(enqueued) >= 1
    assert all(t.domain == Domain.RED for t in enqueued)


async def test_orchestrator_enqueues_all_red_agents_per_target(tmp_path):
    """Each target gets all three red agent tiers."""
    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("10.0.0.0/24", "subnet")

    from orchestrator import Orchestrator
    orch = Orchestrator(sm)

    enqueued: list[AgentTask] = []

    async def fake_submit(task: AgentTask):
        enqueued.append(task)

    with patch.object(orch, "_classify", new=AsyncMock(return_value={"domain": "red", "confidence": 0.95, "reason": "test"})), \
         patch("orchestrator.RBACManager") as mock_rbac, \
         patch("orchestrator.AsyncWorkerPool") as mock_pool_class:
        mock_rbac.enforce_red_team_auth.return_value = True
        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock(side_effect=lambda task: enqueued.append(task))
        mock_pool.run_until_complete = AsyncMock(return_value=[])
        mock_pool_class.return_value = mock_pool
        await orch.route("enumerate services", targets=["10.0.0.1", "10.0.0.2"])

    # 2 targets × 5 red agents = 10 tasks
    assert len(enqueued) == 10
    agent_names = [t.agent_name for t in enqueued]
    assert agent_names.count("pentester_recon") == 2
    assert agent_names.count("pentester_vuln") == 2
    assert agent_names.count("pentester_exploit") == 2
    assert agent_names.count("pentester_lat") == 2
    assert agent_names.count("pentester_ex") == 2


async def test_orchestrator_enqueues_blue_tasks(tmp_path):
    """Blue domain: 3 blue agents, no target-per-agent multiplication."""
    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("internal", "enterprise")

    from orchestrator import Orchestrator
    orch = Orchestrator(sm)

    enqueued: list[AgentTask] = []

    async def fake_submit(task: AgentTask):
        enqueued.append(task)

    with patch.object(orch, "_classify", new=AsyncMock(return_value={"domain": "blue", "confidence": 0.9, "reason": "test"})), \
         patch("orchestrator.AsyncWorkerPool") as mock_pool_class:
        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock(side_effect=lambda task: enqueued.append(task))
        mock_pool.run_until_complete = AsyncMock(return_value=[])
        mock_pool_class.return_value = mock_pool
        await orch.route("analyze firewall logs")

    assert len(enqueued) == 4
    assert all(t.domain == Domain.BLUE for t in enqueued)
    agent_names = {t.agent_name for t in enqueued}
    assert agent_names == {"defender_mon", "defender_ana", "defender_hunt", "defender_res"}


async def test_orchestrator_enqueues_reporter_task(tmp_path):
    """Reporter domain: exactly one reporter_agent task at EXECUTION tier."""
    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("internal", "enterprise")

    from orchestrator import Orchestrator
    orch = Orchestrator(sm)

    enqueued: list[AgentTask] = []

    async def fake_submit(task: AgentTask):
        enqueued.append(task)

    with patch.object(orch, "_classify", new=AsyncMock(return_value={"domain": "reporter", "confidence": 0.85, "reason": "test"})), \
         patch("orchestrator.AsyncWorkerPool") as mock_pool_class:
        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock(side_effect=lambda task: enqueued.append(task))
        mock_pool.run_until_complete = AsyncMock(return_value=[])
        mock_pool_class.return_value = mock_pool
        await orch.route("generate executive summary")

    assert len(enqueued) == 1
    assert enqueued[0].agent_name == "reporter_agent"
    assert enqueued[0].domain == Domain.REPORTER
    assert enqueued[0].tier == AgentTier.EXECUTION


async def test_orchestrator_purple_enqueues_both_red_and_blue(tmp_path):
    """Purple domain: red agents per-target AND blue agents (one set)."""
    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("10.0.0.1", "single-host")

    from orchestrator import Orchestrator
    orch = Orchestrator(sm)

    enqueued: list[AgentTask] = []

    async def fake_submit(task: AgentTask):
        enqueued.append(task)

    with patch.object(orch, "_classify", new=AsyncMock(return_value={"domain": "purple", "confidence": 0.88, "reason": "test"})), \
         patch("orchestrator.RBACManager") as mock_rbac, \
         patch("orchestrator.AsyncWorkerPool") as mock_pool_class:
        mock_rbac.enforce_red_team_auth.return_value = True
        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock(side_effect=lambda task: enqueued.append(task))
        mock_pool.run_until_complete = AsyncMock(return_value=[])
        mock_pool_class.return_value = mock_pool
        await orch.route("purple team exercise", targets=["10.0.0.1"])

    red_tasks = [t for t in enqueued if t.domain == Domain.RED]
    blue_tasks = [t for t in enqueued if t.domain == Domain.BLUE]
    # 1 target × 5 red agents = 5 red tasks; 4 blue agents
    assert len(red_tasks) == 5
    assert len(blue_tasks) == 4


async def test_dispatch_task_success(tmp_path):
    """_dispatch_task wraps a successful _run_agent call in AgentResult(status=success)."""
    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("10.0.0.1", "single-host")

    from orchestrator import Orchestrator
    orch = Orchestrator(sm)

    task = AgentTask(
        domain=Domain.RED,
        tier=AgentTier.RECON,
        agent_name="pentester_recon",
        payload={"target": "10.0.0.1", "task": "recon"},
    )

    with patch.object(orch, "_run_agent", new=AsyncMock(return_value={"output": "scan done"})):
        result = await orch._dispatch_task(task)

    assert result.status == "success"
    assert result.agent_name == "pentester_recon"
    assert result.output == {"output": "scan done"}


async def test_dispatch_task_error(tmp_path):
    """_dispatch_task catches exceptions and returns AgentResult(status=error)."""
    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("10.0.0.1", "single-host")

    from orchestrator import Orchestrator
    orch = Orchestrator(sm)

    task = AgentTask(
        domain=Domain.RED,
        tier=AgentTier.RECON,
        agent_name="pentester_recon",
        payload={"target": "10.0.0.1", "task": "recon"},
    )

    async def boom(_task):
        raise RuntimeError("agent exploded")

    with patch.object(orch, "_run_agent", new=boom):
        result = await orch._dispatch_task(task)

    assert result.status == "error"
    assert "agent exploded" in (result.error_detail or "")


async def test_unknown_domain_not_routed(tmp_path):
    """Unknown domain returns routing dict without enqueuing anything."""
    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("10.0.0.1", "single-host")

    from orchestrator import Orchestrator
    orch = Orchestrator(sm)

    enqueued: list[AgentTask] = []

    async def fake_submit(task: AgentTask):
        enqueued.append(task)

    with patch.object(orch, "_classify", new=AsyncMock(return_value={"domain": "unknown", "confidence": 0.1, "reason": "no idea"})):
        mock_pool = MagicMock()
        mock_pool.submit = fake_submit
        mock_pool.run_until_complete = AsyncMock(return_value=[])
        orch._pool = mock_pool
        result = await orch.route("gibberish input")

    assert result["domain"] == "unknown"
    assert len(enqueued) == 0


async def test_rbac_denial_skips_enqueue(tmp_path):
    """If RBAC denies red access, no tasks are enqueued."""
    from state_manager import StateManager
    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("10.0.0.1", "single-host")

    from orchestrator import Orchestrator
    orch = Orchestrator(sm)

    enqueued: list[AgentTask] = []

    async def fake_submit(task: AgentTask):
        enqueued.append(task)

    with patch.object(orch, "_classify", new=AsyncMock(return_value={"domain": "red", "confidence": 0.9, "reason": "test"})), \
         patch("orchestrator.RBACManager") as mock_rbac:
        mock_rbac.enforce_red_team_auth.return_value = False
        mock_pool = MagicMock()
        mock_pool.submit = fake_submit
        mock_pool.run_until_complete = AsyncMock(return_value=[])
        orch._pool = mock_pool
        await orch.route("attack everything", targets=["10.0.0.1"])

    assert len(enqueued) == 0
