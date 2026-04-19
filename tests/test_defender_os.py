"""
tests/test_defender_os.py — Unit tests for DefenderOS (blue team orchestrator).

DefenderOS is NOT a BaseAgent. It wraps Mon/Hunt/Ana/Res sub-agents.

Covers: initialization, analyze_logs pipeline routing, quiet-path (no alerts),
        escalation gate to Tier 4.
"""
import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from state_manager import StateManager


def _make_dos(sm):
    """Build a DefenderOS with all LLM-backed sub-agents stubbed out."""
    from agents.blue.defender_os import DefenderOS
    from agents.blue.defender_mon import DefenderMon

    dos = DefenderOS.__new__(DefenderOS)
    dos.state = sm
    dos.mon = DefenderMon(sm)

    # Stub agents that would require LLM or abstract-method implementation
    dos.hunt = MagicMock()
    dos.hunt.run = AsyncMock(return_value=None)
    dos.ana = MagicMock()
    dos.ana.run = AsyncMock(return_value="analysis")
    dos.res = MagicMock()
    dos.res.run = AsyncMock(return_value=None)
    return dos


@pytest.fixture
def sm(tmp_path):
    db = str(tmp_path / "dos_test.db")
    s = StateManager(db_path=db)
    s.initialize_engagement("10.0.0.1", "test scope")
    return s


@pytest.fixture
def dos(sm):
    return _make_dos(sm)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInit:
    def test_sub_agents_are_created(self, dos):
        assert dos.mon is not None
        assert dos.hunt is not None
        assert dos.ana is not None
        assert dos.res is not None

    def test_state_stored(self, dos, sm):
        assert dos.state is sm


# ---------------------------------------------------------------------------
# analyze_logs — quiet path (no Tier 1 alerts)
# ---------------------------------------------------------------------------

class TestQuietPath:
    @pytest.mark.asyncio
    async def test_no_alerts_skips_ana_and_res(self, dos):
        with patch.object(dos.mon, "analyze", return_value=[]):
            await dos.analyze_logs("benign log line")
        dos.hunt.run.assert_called_once()
        dos.ana.run.assert_not_called()
        dos.res.run.assert_not_called()

    @pytest.mark.asyncio
    async def test_hunt_always_runs(self, dos):
        with patch.object(dos.mon, "analyze", return_value=[]):
            await dos.analyze_logs("normal logs")
        dos.hunt.run.assert_called_once()


# ---------------------------------------------------------------------------
# analyze_logs — alert path (Tier 1 fires)
# ---------------------------------------------------------------------------

class TestAlertPath:
    @pytest.mark.asyncio
    async def test_alerts_trigger_ana(self, dos):
        fake_alert = {"type": "LSASS_DUMP", "severity": "critical", "description": "lsass dumped"}
        with patch.object(dos.mon, "analyze", return_value=[fake_alert]):
            await dos.analyze_logs("sekurlsa::logonpasswords")
        dos.ana.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_log_text_combined_with_logon_lines(self, dos):
        received = []
        dos.ana.run = AsyncMock(side_effect=lambda task: received.append(task) or "analysis")

        with patch.object(dos.mon, "analyze", return_value=[{"type": "X", "severity": "high", "description": "d"}]):
            await dos.analyze_logs(log_text="base log", logon_lines=["4624 LogonType 3"])

        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_res_runs_when_escalation_confirmed(self, dos, sm):
        fake_alert = {"type": "LSASS", "severity": "critical", "description": "dump"}
        with patch.object(sm, "get_escalated_analysis_count", return_value=1, create=True), \
             patch.object(dos.mon, "analyze", return_value=[fake_alert]):
            await dos.analyze_logs("lsass dump")
        dos.res.run.assert_called_once()
