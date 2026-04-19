import pytest
from unittest.mock import AsyncMock, patch
from core.schemas import AgentTier
from core.mcp_gateway import MCPGateway, GatewayAccessError

LONG_TEXT = " ".join([f"word{i}" for i in range(2000)])


async def test_execution_tier_agent_is_blocked():
    gw = MCPGateway(max_tokens=500)
    with pytest.raises(GatewayAccessError, match="EXECUTION"):
        await gw.query("siem", "get_alerts", {}, caller_tier=AgentTier.EXECUTION)


async def test_short_response_passes_through_unmodified():
    gw = MCPGateway(max_tokens=500)
    short = "Only 5 words here."
    with patch.object(gw, "_call_mcp_server", new=AsyncMock(return_value=short)):
        result = await gw.query("siem", "get_alerts", {}, caller_tier=AgentTier.RECON)
    assert result == short


async def test_long_response_is_truncated_to_max_tokens():
    gw = MCPGateway(max_tokens=100)
    with patch.object(gw, "_call_mcp_server", new=AsyncMock(return_value=LONG_TEXT)), \
         patch.object(gw, "_summarize", new=AsyncMock(return_value="summary text")):
        result = await gw.query("siem", "get_alerts", {}, caller_tier=AgentTier.ANALYSIS)
    assert result == "summary text"


async def test_unknown_server_raises_value_error():
    gw = MCPGateway(max_tokens=500)
    with pytest.raises(ValueError, match="Unknown MCP server"):
        await gw.query("nonexistent_server", "tool", {}, caller_tier=AgentTier.RECON)
