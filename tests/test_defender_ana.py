"""
tests/test_defender_ana.py — Unit tests for DefenderAna IOC enrichment integration.

Covers:
- enrich_ioc tool present in schema; write_analysis preserved
- enrich_ioc constructs MCPGateway bound to the agent's real tier
- An IP routes to threat_intel / query_abuseipdb ({"ip": ...})
- A hash or domain routes to threat_intel / query_virustotal ({"resource": ...})
- Empty ioc short-circuits before touching the gateway
- The gateway gate is enforced against the agent's bound tier (construction-time):
  an EXECUTION-tier agent cannot reach servers via the enrich_ioc code path
- write_analysis still persists as before
"""
import os
import sys
import pytest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from state_manager import StateManager
from agents.blue.defender_ana import DefenderAna
from core.schemas import AgentTier
from core.mcp_gateway import MCPGateway, GatewayAccessError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sm(tmp_path):
    db = str(tmp_path / "ana_test.db")
    s = StateManager(db_path=db)
    s.initialize_engagement("192.168.1.1", "test scope")
    return s


@pytest.fixture
def agent(sm):
    a = DefenderAna(sm)
    # The Orchestrator assigns the real tier post-construction; ana is ANALYSIS.
    a.tier = AgentTier.ANALYSIS
    return a


# ---------------------------------------------------------------------------
# Tool schema
# ---------------------------------------------------------------------------

class TestAnaToolSchema:
    def test_get_ana_tools_returns_list(self, agent):
        assert isinstance(agent._get_ana_tools(), list)

    def test_enrich_ioc_in_schema(self, agent):
        names = [t["name"] for t in agent._get_ana_tools()]
        assert "enrich_ioc" in names

    def test_write_analysis_still_in_schema(self, agent):
        names = [t["name"] for t in agent._get_ana_tools()]
        assert "write_analysis" in names

    def test_enrich_ioc_requires_ioc(self, agent):
        tool = next(t for t in agent._get_ana_tools() if t["name"] == "enrich_ioc")
        assert tool["input_schema"]["required"] == ["ioc"]


# ---------------------------------------------------------------------------
# enrich_ioc routing — gateway bound to the agent's real tier
# ---------------------------------------------------------------------------

class TestEnrichIocRouting:
    @pytest.mark.asyncio
    async def test_gateway_constructed_with_agents_real_tier(self, agent):
        """The gateway is bound to self.tier at construction — not a per-call literal."""
        mock_query = AsyncMock(return_value='{"abuseConfidenceScore": 100}')
        with patch("agents.blue.defender_ana.MCPGateway") as MockGateway:
            MockGateway.return_value.query = mock_query
            await agent._execute_ana_tool("enrich_ioc", {"ioc": "45.33.32.156"})
        MockGateway.assert_called_once_with(caller_tier=AgentTier.ANALYSIS)

    @pytest.mark.asyncio
    async def test_ip_routes_to_abuseipdb(self, agent):
        mock_query = AsyncMock(return_value='{"abuseConfidenceScore": 100}')
        with patch("agents.blue.defender_ana.MCPGateway") as MockGateway:
            MockGateway.return_value.query = mock_query
            await agent._execute_ana_tool("enrich_ioc", {"ioc": "185.220.101.47"})
        mock_query.assert_awaited_once()
        args = mock_query.await_args[0]
        assert args[0] == "threat_intel"
        assert args[1] == "query_abuseipdb"
        assert args[2] == {"ip": "185.220.101.47"}
        # caller_tier is bound at construction, never a per-call arg.
        assert "caller_tier" not in mock_query.await_args[1]

    @pytest.mark.asyncio
    async def test_ipv6_routes_to_abuseipdb(self, agent):
        mock_query = AsyncMock(return_value="{}")
        with patch("agents.blue.defender_ana.MCPGateway") as MockGateway:
            MockGateway.return_value.query = mock_query
            await agent._execute_ana_tool("enrich_ioc", {"ioc": "2001:db8::1"})
        assert mock_query.await_args[0][1] == "query_abuseipdb"

    @pytest.mark.asyncio
    async def test_hash_routes_to_virustotal(self, agent):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        mock_query = AsyncMock(return_value='{"data": []}')
        with patch("agents.blue.defender_ana.MCPGateway") as MockGateway:
            MockGateway.return_value.query = mock_query
            await agent._execute_ana_tool("enrich_ioc", {"ioc": sha256})
        args = mock_query.await_args[0]
        assert args[1] == "query_virustotal"
        assert args[2] == {"resource": sha256}

    @pytest.mark.asyncio
    async def test_domain_routes_to_virustotal(self, agent):
        mock_query = AsyncMock(return_value='{"data": []}')
        with patch("agents.blue.defender_ana.MCPGateway") as MockGateway:
            MockGateway.return_value.query = mock_query
            await agent._execute_ana_tool("enrich_ioc", {"ioc": "evil.example.com"})
        args = mock_query.await_args[0]
        assert args[1] == "query_virustotal"
        assert args[2] == {"resource": "evil.example.com"}

    @pytest.mark.asyncio
    async def test_empty_ioc_short_circuits_before_gateway(self, agent):
        with patch("agents.blue.defender_ana.MCPGateway") as MockGateway:
            result = agent._execute_ana_tool("enrich_ioc", {"ioc": "   "})
        MockGateway.assert_not_called()
        assert "error" in result.lower()


# ---------------------------------------------------------------------------
# Gateway tier gate — enforced against the construction-bound tier
# ---------------------------------------------------------------------------

class TestGatewayTierEnforcement:
    @pytest.mark.asyncio
    async def test_execution_agent_cannot_reach_servers_via_enrich_path(self, sm):
        """Regression: an EXECUTION-tier agent cannot spoof its way to a server.

        Running the real enrich_ioc path (no mocked gateway), the gateway is bound
        to the agent's true tier and fails closed for EXECUTION.
        """
        a = DefenderAna(sm)
        a.tier = AgentTier.EXECUTION
        coro = a._execute_ana_tool("enrich_ioc", {"ioc": "185.220.101.47"})
        with pytest.raises(GatewayAccessError, match="EXECUTION"):
            await coro


# ---------------------------------------------------------------------------
# write_analysis — existing behaviour preserved
# ---------------------------------------------------------------------------

class TestWriteAnalysis:
    def test_write_analysis_persists_and_reports(self, agent):
        result = agent._execute_ana_tool(
            "write_analysis",
            {
                "alert_id": "alert-1",
                "verdict": "true_positive",
                "severity": "P1",
                "reasoning": "LSASS access observed on host WS01",
                "escalate": True,
            },
        )
        assert "true_positive" in result
        assert "ESCALATING" in result

    def test_unknown_tool_falls_back_to_base_execute_tool(self, agent):
        with patch.object(agent, "_execute_tool", return_value="base_result") as mock_base:
            result = agent._execute_ana_tool("unknown_tool", {"foo": "bar"})
        mock_base.assert_called_once_with("unknown_tool", {"foo": "bar"})
        assert result == "base_result"
