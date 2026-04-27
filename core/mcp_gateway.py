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
    # NOTE: "lsp" is intentionally absent — core.lsp_server is a pygls server
    # (no handle_call_tool). Agents interact with LSP via core.lsp_server directly.
    "atomic":          "mcp_servers.atomic.server",
    "graph":           "mcp_servers.graph.server",
    "memory":          "mcp_servers.memory.server",
    "pivot":           "mcp_servers.pivot.server",
    "red_recon":       "mcp_servers.red_recon.server",
    "threat_intel":    "mcp_servers.threat_intel.server",
    "vault":           "mcp_servers.vault.server",
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

    def __init__(self, max_tokens: int = 500, llm_client=None, llm_model: str | None = None) -> None:
        self.max_tokens = max_tokens
        self._llm_client = llm_client
        self._llm_model = llm_model

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

        summary = await self._summarize(raw)
        # Enforce hard word cap regardless of what the LLM returned
        words = summary.split()
        if len(words) > self.max_tokens:
            summary = " ".join(words[: self.max_tokens])
        return summary

    async def _call_mcp_server(self, server_name: str, tool_name: str, arguments: dict) -> str:
        """
        Invoke a named MCP server tool in-process.

        Imports the server module and calls `handle_call_tool` directly.
        All mcp_servers use `mcp.server.Server` whose `@server.call_tool()`
        decorator returns the original function unchanged, leaving it accessible
        at module scope as `handle_call_tool`.

        Raises RuntimeError if the module does not expose `handle_call_tool`
        (e.g. the LSP server, which uses pygls instead of mcp.server.Server).
        """
        import importlib

        module_path = _SERVER_REGISTRY[server_name]
        module = importlib.import_module(module_path)

        handler = getattr(module, "handle_call_tool", None)
        if handler is None:
            raise RuntimeError(
                f"Module '{module_path}' (server '{server_name}') does not expose "
                "'handle_call_tool'. Only mcp.server.Server-based modules are "
                "supported for in-process dispatch. "
                f"Available names: {[n for n in dir(module) if not n.startswith('_')]}"
            )

        result = await handler(tool_name, arguments or {})

        # result is list[TextContent | ImageContent | EmbeddedResource]
        if isinstance(result, list):
            parts = [item.text for item in result if hasattr(item, "text") and item.text]
            return "\n".join(parts) if parts else ""
        return str(result)

    async def _summarize(self, text: str) -> str:
        """
        Use the local LLM to compress `text` to at most self.max_tokens words.

        Never call this with text already within the limit — check word count first.
        """
        word_limit = self.max_tokens

        if self._llm_client is not None:
            client = self._llm_client
            model = self._llm_model or "local"
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
                    {"role": "user", "content": text[: word_limit * 10]},
                ],
                max_tokens=word_limit * 2,
            )
        else:
            from llm_client import LLMClient
            client, model, _ = LLMClient.create(brain_tier="local")
            async with client:
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
                        {"role": "user", "content": text[: word_limit * 10]},
                    ],
                    max_tokens=word_limit * 2,
                )

        content = response.choices[0].message.content
        if not content:
            raise RuntimeError(
                f"LLM summarisation returned empty content "
                f"({len(text.split())} words input, max_tokens={self.max_tokens})"
            )
        return content.strip()
