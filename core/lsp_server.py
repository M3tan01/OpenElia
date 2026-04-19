"""
core/lsp_server.py — Language Server Protocol server for OpenElia.

Provides code intelligence for .py files in the project using pygls.
Access is gated exclusively through MCPGateway (Tier-1/2 agents only).

To run standalone for development:
    python -m core.lsp_server
"""

from __future__ import annotations

from pygls.lsp.server import LanguageServer
from lsprotocol.types import (
    TEXT_DOCUMENT_COMPLETION,
    CompletionItem,
    CompletionItemKind,
    CompletionList,
    CompletionParams,
)

server = LanguageServer("openelia-lsp", "v0.1")

# OpenElia-specific completion tokens surfaced in agent code editors
_ELIA_TOKENS: list[CompletionItem] = [
    CompletionItem(label="AgentTask", kind=CompletionItemKind.Class,
                   detail="core.schemas.AgentTask — inter-agent task descriptor"),
    CompletionItem(label="AgentResult", kind=CompletionItemKind.Class,
                   detail="core.schemas.AgentResult — structured agent output"),
    CompletionItem(label="AsyncWorkerPool", kind=CompletionItemKind.Class,
                   detail="core.worker_pool.AsyncWorkerPool — tier-based pool"),
    CompletionItem(label="MCPGateway", kind=CompletionItemKind.Class,
                   detail="core.mcp_gateway.MCPGateway — gated MCP query layer"),
    CompletionItem(label="pre_run_hook", kind=CompletionItemKind.Function,
                   detail="core.hooks.pre_run_hook — inject JIT context"),
    CompletionItem(label="post_run_hook", kind=CompletionItemKind.Function,
                   detail="core.hooks.post_run_hook — persist result, free context"),
    CompletionItem(label="error_hook", kind=CompletionItemKind.Function,
                   detail="core.hooks.error_hook — log structured error payload"),
]


@server.feature(TEXT_DOCUMENT_COMPLETION)
def completions(params: CompletionParams) -> CompletionList:
    """Return OpenElia-specific completion items."""
    return CompletionList(is_incomplete=False, items=_ELIA_TOKENS)


def start_lsp_server(host: str = "127.0.0.1", port: int = 2087) -> None:
    """Start the LSP server in TCP mode."""
    server.start_tcp(host, port)


if __name__ == "__main__":
    start_lsp_server()
