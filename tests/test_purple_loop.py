"""
tests/test_purple_loop.py — Purple team feedback loop.

Covers:
  - force_domain bypasses classifier
  - route() called with "red" then "blue" then "reporter" in correct order
  - early termination when coverage >= 100%
  - N iterations when coverage stays low
  - task strings include blue feedback in later iterations
  - loop adapts red task based on previous blue alerts
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_args(iterations=2, target="10.0.0.1", scope=None, task=None,
               stealth=False, proxy_port=None, brain_tier="local", resume=False):
    return SimpleNamespace(
        iterations=iterations,
        target=target,
        scope=scope,
        task=task,
        stealth=stealth,
        proxy_port=proxy_port,
        brain_tier=brain_tier,
        resume=resume,
    )


def _mock_purple_context(state_data, domains_called=None, red_tasks=None):
    """
    Return a context manager that patches StateManager and Orchestrator
    the way cmd_purple sees them (local imports resolved via source module).
    """
    async def fake_route(task, targets=None, stealth=False, proxy_port=None,
                         brain_tier="local", force_domain=None, **kw):
        if domains_called is not None:
            domains_called.append(force_domain)
        if red_tasks is not None and force_domain == "red":
            red_tasks.append(task)

    mock_sm = MagicMock()
    mock_sm.read.return_value = state_data
    mock_orch = MagicMock()
    mock_orch.route = AsyncMock(side_effect=fake_route)

    return (
        patch("state_manager.StateManager", return_value=mock_sm),
        patch("orchestrator.Orchestrator", return_value=mock_orch),
        patch("main._require_api_key"),
    )


# ---------------------------------------------------------------------------
# Orchestrator.route — force_domain
# ---------------------------------------------------------------------------

async def test_force_domain_skips_classifier(tmp_path):
    from state_manager import StateManager
    from orchestrator import Orchestrator

    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("10.0.0.1", "test")
    orch = Orchestrator(sm)

    with patch.object(orch, "_classify", new=AsyncMock()) as mock_classify, \
         patch("orchestrator.RBACManager") as mock_rbac, \
         patch("orchestrator.AsyncWorkerPool") as mock_pool_class:
        mock_rbac.enforce_red_team_auth.return_value = True
        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock()
        mock_pool.run_until_complete = AsyncMock(return_value=[])
        mock_pool_class.return_value = mock_pool

        await orch.route("do recon", targets=["10.0.0.1"], force_domain="red")

    mock_classify.assert_not_called()


async def test_force_domain_uses_provided_domain(tmp_path):
    from state_manager import StateManager
    from orchestrator import Orchestrator

    sm = StateManager(db_path=str(tmp_path / "test.db"))
    sm.initialize_engagement("10.0.0.1", "test")
    orch = Orchestrator(sm)

    with patch.object(orch, "_classify", new=AsyncMock(return_value={"domain": "unknown", "confidence": 0.1, "reason": "x"})), \
         patch("orchestrator.RBACManager") as mock_rbac, \
         patch("orchestrator.AsyncWorkerPool") as mock_pool_class:
        mock_rbac.enforce_red_team_auth.return_value = True
        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock()
        mock_pool.run_until_complete = AsyncMock(return_value=[])
        mock_pool_class.return_value = mock_pool

        result = await orch.route("task", targets=["10.0.0.1"], force_domain="blue")

    assert result["domain"] == "blue"


# ---------------------------------------------------------------------------
# cmd_purple — phase ordering
# ---------------------------------------------------------------------------

async def test_purple_loop_calls_red_then_blue_then_reporter():
    """Each iteration must call red phase first, blue phase second; reporter at end."""
    from main import cmd_purple

    domains_called = []
    patches = _mock_purple_context({"findings": [], "blue_alerts": []}, domains_called)

    with patches[0], patches[1], patches[2]:
        await cmd_purple(_make_args(iterations=2))

    # Expect: red, blue, red, blue, reporter
    assert domains_called[0] == "red"
    assert domains_called[1] == "blue"
    assert domains_called[2] == "red"
    assert domains_called[3] == "blue"
    assert domains_called[-1] == "reporter"


async def test_purple_loop_always_ends_with_reporter():
    from main import cmd_purple

    domains_called = []
    patches = _mock_purple_context({"findings": [], "blue_alerts": []}, domains_called)

    with patches[0], patches[1], patches[2]:
        await cmd_purple(_make_args(iterations=1))

    assert domains_called[-1] == "reporter"


# ---------------------------------------------------------------------------
# cmd_purple — early termination on full coverage
# ---------------------------------------------------------------------------

async def test_purple_loop_terminates_early_when_full_coverage():
    """If blue produces alerts >= findings count, loop exits before N iterations."""
    from main import cmd_purple

    domains_called = []
    state_full = {
        "findings": [{"title": "SQLi"}, {"title": "XSS"}],
        "blue_alerts": [{"type": "a1"}, {"type": "a2"}],
    }
    patches = _mock_purple_context(state_full, domains_called)

    with patches[0], patches[1], patches[2]:
        await cmd_purple(_make_args(iterations=5))  # max 5, should exit at 1

    assert domains_called.count("red") == 1
    assert domains_called.count("blue") == 1
    assert domains_called[-1] == "reporter"


async def test_purple_loop_runs_all_iterations_when_coverage_stays_low():
    """If blue never catches up, all N iterations run."""
    from main import cmd_purple

    domains_called = []
    state_low = {
        "findings": [{"title": "f1"}, {"title": "f2"}, {"title": "f3"}],
        "blue_alerts": [],
    }
    patches = _mock_purple_context(state_low, domains_called)

    with patches[0], patches[1], patches[2]:
        await cmd_purple(_make_args(iterations=3))

    assert domains_called.count("red") == 3
    assert domains_called.count("blue") == 3
    assert domains_called[-1] == "reporter"


# ---------------------------------------------------------------------------
# cmd_purple — adaptive task strings
# ---------------------------------------------------------------------------

async def test_purple_loop_red_task_adapts_with_blue_alerts_in_iteration_2():
    """Second red iteration task string must reference blue detection types."""
    from main import cmd_purple

    red_tasks = []
    # 1 finding, 1 alert — full coverage so only 1 iteration, but we need 2
    # Use low coverage (alerts empty) so both iterations run
    state_with_alerts = {
        "findings": [{"title": "f1"}],
        "blue_alerts": [{"type": "port_scan_alert"}],
    }

    # Override: make it return empty alerts first call, populated second
    call_idx = [0]
    # 3 findings, 1 alert → coverage 33% → loop keeps running
    # Alerts present so iter 2 red task gets "Blue detected" adaptation
    low_cov_state  = {"findings": [{"title": "f1"}, {"title": "f2"}, {"title": "f3"}], "blue_alerts": []}
    after_blue_1   = {"findings": [{"title": "f1"}, {"title": "f2"}, {"title": "f3"}], "blue_alerts": [{"type": "port_scan_alert"}]}

    async def fake_route(task, targets=None, stealth=False, proxy_port=None,
                         brain_tier="local", force_domain=None, **kw):
        call_idx[0] += 1
        if force_domain == "red":
            red_tasks.append(task)

    mock_sm = MagicMock()
    # reads: after_red_1=low_cov, after_blue_1=has_alert, after_red_2=has_alert, after_blue_2=has_alert
    mock_sm.read.side_effect = [low_cov_state, after_blue_1, after_blue_1, after_blue_1, after_blue_1]
    mock_orch = MagicMock()
    mock_orch.route = AsyncMock(side_effect=fake_route)

    with patch("state_manager.StateManager", return_value=mock_sm), \
         patch("orchestrator.Orchestrator", return_value=mock_orch), \
         patch("main._require_api_key"):
        await cmd_purple(_make_args(iterations=2))

    assert len(red_tasks) == 2
    assert "Blue detected" not in red_tasks[0]
    assert "Blue detected" in red_tasks[1]
