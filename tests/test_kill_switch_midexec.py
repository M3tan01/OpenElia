"""
tests/test_kill_switch_midexec.py — kill-switch aborts execution mid-flight.

CLAUDE.md's operational standard: "Check the is_locked flag before every tool
execution. If set, terminate immediately." BaseAgent._execute_tool enforces this
by calling _check_kill_switch() as its first line (agents/base_agent.py:217),
which re-reads is_locked from SQLite and raises SystemExit when set.

The rail-matrix suite pins that the *engine gate* deliberately does NOT consult
is_locked (that would deadlock cleanup rollback). This file pins the OTHER half:
the *agent layer* does, and an operator flipping the switch between tool calls in
a long EXECUTION-tier task aborts the next call — it does not run to completion.

Construction mirrors test_pentester_lat.py: a real StateManager on a tmp db and a
real agent (conftest seeds the model config the constructor resolves).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from state_manager import StateManager
from agents.red.pentester_lat import PentesterLat


@pytest.fixture
def sm(tmp_path):
    s = StateManager(db_path=str(tmp_path / "kill_test.db"))
    s.initialize_engagement("10.0.0.1", "test scope")
    return s


@pytest.fixture
def agent(sm):
    return PentesterLat(sm)


class TestKillSwitchMidExecution:
    def test_check_kill_switch_raises_when_locked(self, sm, agent):
        """Locked engagement → _check_kill_switch raises SystemExit; unlocked → no-op."""
        assert agent._check_kill_switch() is None   # unlocked: passes silently
        sm.set_locked(True)
        with pytest.raises(SystemExit, match="kill-switch"):
            agent._check_kill_switch()

    def test_execute_tool_aborts_when_locked(self, sm, agent):
        """A benign tool runs while unlocked, then is refused once locked."""
        # Unlocked: read_state returns real state JSON, no raise.
        out = agent._execute_tool("read_state", {})
        assert isinstance(out, str)

        # Operator throws the kill-switch.
        sm.set_locked(True)
        with pytest.raises(SystemExit):
            agent._execute_tool("read_state", {})

    def test_switch_flipped_between_tools_aborts_next_call(self, sm, agent):
        """Long EXECUTION task: tool N completes, operator locks, tool N+1 aborts.

        Simulates the real dispatch loop calling _execute_tool sequentially. The
        abort must land on the NEXT tool after the flip — proving enforcement is
        per-call (re-read from SQLite), not a one-time check at task start.
        """
        calls_completed = 0

        # Tool 1 — unlocked, completes.
        agent._execute_tool("read_state", {})
        calls_completed += 1

        # Operator flips the switch mid-task (e.g. from the webdash control panel).
        sm.set_locked(True)

        # Tool 2 — must abort, not execute.
        with pytest.raises(SystemExit):
            agent._execute_tool("read_state", {})

        assert calls_completed == 1  # only the pre-lock tool ran

    def test_unlock_restores_execution(self, sm, agent):
        """set_locked(False) clears the abort — the switch is reversible."""
        sm.set_locked(True)
        with pytest.raises(SystemExit):
            agent._check_kill_switch()

        sm.set_locked(False)
        assert agent._check_kill_switch() is None
        assert isinstance(agent._execute_tool("read_state", {}), str)
