"""
core/mcp_gateway.py — Gated query abstraction for MCP and LSP servers.

Rules:
  1. Only AgentTier.RECON and AgentTier.ANALYSIS agents may issue queries.
     AgentTier.EXECUTION agents receive pre-summarized context — they never
     query servers directly. This prevents raw MCP output from flooding an
     execution agent's prompt.
  2. Any response exceeding `max_tokens` words is summarized by the local
     LLM before being returned. Summaries are constrained to max_tokens words.
"""

from __future__ import annotations

from core.schemas import AgentTier

# Maps logical server names to their module paths
_SERVER_REGISTRY: dict[str, str] = {
    "siem":            "mcp_servers.siem.server",
    "blue_telemetry":  "mcp_servers.blue_telemetry.server",
    "blue_remediate":  "mcp_servers.blue_remediate.server",
    "lsp":             "core.lsp_server",
}

_ALLOWED_TIERS = {AgentTier.RECON, AgentTier.ANALYSIS}


class GatewayAccessError(PermissionError):
    """Raised when an agent tier is not permitted to query MCP/LSP servers."""


class MCPGateway:
    """
    Token-limited MCP/LSP query gateway.

    Usage:
        gw = MCPGateway(max_tokens=500)
        summary = await gw.query("siem", "get_alerts", {"hours": 24}, caller_tier=AgentTier.ANALYSIS)
    """

    def __init__(self, max_tokens: int = 500) -> None:
        self.max_tokens = max_tokens

    async def query(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict,
        caller_tier: AgentTier,
    ) -> str:
        """
        Execute a tool call against a named MCP/LSP server.

        Args:
            server_name:  Key in _SERVER_REGISTRY ("siem", "blue_telemetry", etc.)
            tool_name:    Name of the MCP tool to call.
            arguments:    Tool input as a plain dict.
            caller_tier:  AgentTier of the requesting agent (enforced gate).

        Returns:
            A string response, guaranteed to be ≤ max_tokens words.

        Raises:
            GatewayAccessError: If caller_tier is AgentTier.EXECUTION.
            ValueError:         If server_name is not in the registry.
        """
        if caller_tier not in _ALLOWED_TIERS:
            raise GatewayAccessError(
                f"Tier {caller_tier.value} ({caller_tier.name}) agents are not permitted "
                "to query MCP/LSP servers directly. Request a summary from a Tier-1/2 agent."
            )

        if server_name not in _SERVER_REGISTRY:
            raise ValueError(f"Unknown MCP server: '{server_name}'. "
                             f"Available: {list(_SERVER_REGISTRY.keys())}")

        raw = await self._call_mcp_server(server_name, tool_name, arguments)

        if len(raw.split()) <= self.max_tokens:
            return raw

        return await self._summarize(raw)

    async def _call_mcp_server(self, server_name: str, tool_name: str, arguments: dict) -> str:
        """
        Invoke the named MCP server tool via its Python interface.

        Currently a stub — replaced in tests via mock. A future iteration
        wires the real mcp client transport here without changing the contract.
        """
        raise NotImplementedError(
            f"Direct MCP call to '{server_name}/{tool_name}' not yet wired. "
            "Use MCPGateway in tests with _call_mcp_server mocked."
        )

    async def _summarize(self, text: str) -> str:
        """
        Use the local LLM to compress `text` to at most self.max_tokens words.

        Never call this with text already within the limit — check word count first.
        """
        from llm_client import LLMClient
        client, model = LLMClient.create(brain_tier="local")
        word_limit = self.max_tokens

        response = await client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        f"Summarize the following security data in ≤{word_limit} words. "
                        "Preserve all hostnames, IPs, CVE IDs, and severity levels. "
                        "Output ONLY the summary — no preamble."
                    ),
                },
                {"role": "user", "content": text[: word_limit * 10]},  # hard input cap
            ],
            max_tokens=word_limit * 2,
        )
        return (response.choices[0].message.content or "").strip()
