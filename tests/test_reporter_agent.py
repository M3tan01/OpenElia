"""
tests/test_reporter_agent.py — ReporterAgent report generation.

Covers: run() calls artifact_manager and graph_manager with state data,
        report includes chain-of-custody table, stores report artifact,
        stores MITRE heatmap artifact, exception propagates on LLM failure.
"""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call


@pytest.fixture()
def mock_state(tmp_path):
    sm = MagicMock()
    sm.read.return_value = {
        "engagement": {"id": "eng-001", "target": "10.0.0.1"},
        "findings": [
            {"title": "SQLi", "severity": "critical", "host": "10.0.0.1", "mitre_ttp": "T1190"},
        ],
        "blue_alerts": [
            {"type": "sql_injection_attempt", "severity": "high"},
        ],
    }
    return sm


@pytest.fixture()
def mock_artifact_manager():
    am = MagicMock()
    am.get_chain_of_custody.return_value = [
        {"timestamp": "2024-01-01T00:00:00", "source_agent": "recon",
         "filename": "scan.enc", "sha256": "a" * 64, "status": "ACQUIRED"},
    ]
    am.store_artifact.return_value = {"path": "/tmp/x.enc", "sha256": "b" * 64, "status": "stored"}
    return am


@pytest.fixture()
def mock_graph_manager():
    gm = MagicMock()
    gm.get_mitre_heatmap.return_value = {
        "Initial Access": {"coverage_pct": 50.0, "tested_ttps": ["T1190"], "missing_ttps": ["T1078"]},
    }
    return gm


@pytest.fixture()
def reporter(mock_state, mock_artifact_manager, mock_graph_manager):
    with patch("agents.reporter_agent.ArtifactManager", return_value=mock_artifact_manager), \
         patch("agents.reporter_agent.GraphManager", return_value=mock_graph_manager):
        from agents.reporter_agent import ReporterAgent
        agent = ReporterAgent(mock_state, brain_tier="local")
        agent.artifact_manager = mock_artifact_manager
        agent.graph_manager = mock_graph_manager
        return agent


class TestReporterAgentRun:
    async def test_calls_get_chain_of_custody(self, reporter, mock_artifact_manager):
        with patch.object(reporter, "_call_with_tools", new=AsyncMock(return_value="## Report content")), \
             patch.object(reporter, "_build_system_prompt", return_value="sys"), \
             patch.object(reporter, "_get_standard_tools", return_value=[]):
            await reporter.run()
        mock_artifact_manager.get_chain_of_custody.assert_called_once()

    async def test_calls_get_mitre_heatmap_with_findings(self, reporter, mock_state, mock_graph_manager):
        with patch.object(reporter, "_call_with_tools", new=AsyncMock(return_value="## Report content")), \
             patch.object(reporter, "_build_system_prompt", return_value="sys"), \
             patch.object(reporter, "_get_standard_tools", return_value=[]):
            await reporter.run()
        findings = mock_state.read()["findings"]
        mock_graph_manager.get_mitre_heatmap.assert_called_once_with(findings)

    async def test_report_includes_chain_of_custody_table(self, reporter):
        with patch.object(reporter, "_call_with_tools", new=AsyncMock(return_value="## Report")), \
             patch.object(reporter, "_build_system_prompt", return_value="sys"), \
             patch.object(reporter, "_get_standard_tools", return_value=[]):
            result = await reporter.run()
        assert "Forensic Chain of Custody" in result
        assert "scan.enc" in result

    async def test_stores_report_artifact(self, reporter, mock_artifact_manager):
        with patch.object(reporter, "_call_with_tools", new=AsyncMock(return_value="## Report")), \
             patch.object(reporter, "_build_system_prompt", return_value="sys"), \
             patch.object(reporter, "_get_standard_tools", return_value=[]):
            await reporter.run()
        calls = mock_artifact_manager.store_artifact.call_args_list
        filenames = [c[1].get("filename", c[0][1] if len(c[0]) > 1 else "") for c in calls]
        assert any("Final_Report" in str(f) for f in filenames)

    async def test_stores_mitre_heatmap_artifact(self, reporter, mock_artifact_manager):
        with patch.object(reporter, "_call_with_tools", new=AsyncMock(return_value="## Report")), \
             patch.object(reporter, "_build_system_prompt", return_value="sys"), \
             patch.object(reporter, "_get_standard_tools", return_value=[]):
            await reporter.run()
        calls = mock_artifact_manager.store_artifact.call_args_list
        filenames = [c[1].get("filename", c[0][1] if len(c[0]) > 1 else "") for c in calls]
        assert any("MITRE_Heatmap" in str(f) for f in filenames)

    async def test_two_artifacts_stored_per_run(self, reporter, mock_artifact_manager):
        with patch.object(reporter, "_call_with_tools", new=AsyncMock(return_value="## Report")), \
             patch.object(reporter, "_build_system_prompt", return_value="sys"), \
             patch.object(reporter, "_get_standard_tools", return_value=[]):
            await reporter.run()
        assert mock_artifact_manager.store_artifact.call_count == 2

    async def test_coc_sha256_truncated_in_table(self, reporter):
        """Chain of custody table shows only first 16 chars of SHA-256."""
        with patch.object(reporter, "_call_with_tools", new=AsyncMock(return_value="## Report")), \
             patch.object(reporter, "_build_system_prompt", return_value="sys"), \
             patch.object(reporter, "_get_standard_tools", return_value=[]):
            result = await reporter.run()
        # sha256 is 64 'a's; table should show first 16 + '...'
        assert "aaaaaaaaaaaaaaaa..." in result

    async def test_llm_failure_propagates(self, reporter):
        with patch.object(reporter, "_call_with_tools", new=AsyncMock(side_effect=RuntimeError("LLM down"))), \
             patch.object(reporter, "_build_system_prompt", return_value="sys"), \
             patch.object(reporter, "_get_standard_tools", return_value=[]):
            with pytest.raises(RuntimeError, match="LLM down"):
                await reporter.run()
