import pytest
from unittest.mock import AsyncMock, patch
from core.schemas import AgentTier
from core.mcp_gateway import MCPGateway, GatewayAccessError

LONG_TEXT = " ".join([f"word{i}" for i in range(2000)])


async def test_execution_tier_agent_is_blocked():
    # Tier is bound at construction — an EXECUTION-bound gateway refuses to query.
    gw = MCPGateway(max_tokens=500, caller_tier=AgentTier.EXECUTION)
    with pytest.raises(GatewayAccessError, match="EXECUTION"):
        await gw.query("siem", "get_alerts", {})


async def test_unset_tier_fails_closed():
    # No tier bound (None) → gateway must refuse. The gate fails closed so an agent
    # that never had its tier assigned cannot reach servers by omission.
    gw = MCPGateway(max_tokens=500)
    with pytest.raises(GatewayAccessError, match="no assigned tier"):
        await gw.query("siem", "get_alerts", {})


async def test_short_response_passes_through_unmodified():
    gw = MCPGateway(max_tokens=500, caller_tier=AgentTier.RECON)
    short = "Only 5 words here."
    with patch.object(gw, "_call_mcp_server", new=AsyncMock(return_value=short)):
        result = await gw.query("siem", "get_alerts", {})
    assert result == short


async def test_long_response_is_truncated_to_max_tokens():
    gw = MCPGateway(max_tokens=100, caller_tier=AgentTier.ANALYSIS)
    with patch.object(gw, "_call_mcp_server", new=AsyncMock(return_value=LONG_TEXT)), \
         patch.object(gw, "_summarize", new=AsyncMock(return_value="summary text")):
        result = await gw.query("siem", "get_alerts", {})
    assert result == "summary text"


async def test_unknown_server_raises_value_error():
    gw = MCPGateway(max_tokens=500, caller_tier=AgentTier.RECON)
    with pytest.raises(ValueError, match="Unknown MCP server"):
        await gw.query("nonexistent_server", "tool", {})


async def test_summary_result_is_hard_capped_to_max_tokens():
    gw = MCPGateway(max_tokens=5, caller_tier=AgentTier.RECON)
    over_limit_summary = " ".join([f"w{i}" for i in range(20)])  # 20 words
    with patch.object(gw, "_call_mcp_server", new=AsyncMock(return_value=LONG_TEXT)), \
         patch.object(gw, "_summarize", new=AsyncMock(return_value=over_limit_summary)):
        result = await gw.query("siem", "get_alerts", {})
    assert len(result.split()) <= 5
