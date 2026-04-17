#!/usr/bin/env python3
"""
mcp_servers/pivot/server.py — Network pivoting MCP server.

Pivot records are stored in the engagement SQLite database (pivot_sessions table)
so they are visible in the dashboard, status command, and forensic archive.

Note: tunnel/proxy creation is currently a simulation stub. Replace the handler
bodies with real SSH/chisel/ligolo commands once your lab environment is configured.
"""
import asyncio
import json
import os
import sys
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from state_manager import StateManager

server = Server("mcp-pivot")


def _get_state() -> StateManager:
    return StateManager()


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="create_tunnel",
            description="Create a secure SSH tunnel to a compromised host and record it in the engagement database.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target":        {"type": "string",  "description": "Compromised host to pivot through"},
                    "local_port":    {"type": "integer", "description": "Local port to listen on"},
                    "remote_target": {"type": "string",  "description": "Destination host inside target network"},
                    "remote_port":   {"type": "integer", "description": "Destination port"},
                },
                "required": ["target", "local_port", "remote_target", "remote_port"],
            },
        ),
        types.Tool(
            name="start_socks_proxy",
            description="Start a SOCKS5 proxy on a local port through a compromised host and record it in the engagement database.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target":     {"type": "string",  "description": "Compromised host to pivot through"},
                    "local_port": {"type": "integer", "description": "Local port to listen on (e.g. 9050)"},
                },
                "required": ["target", "local_port"],
            },
        ),
        types.Tool(
            name="list_pivots",
            description="List all active tunnels and proxies recorded in the engagement database.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    state = _get_state()
    arguments = arguments or {}

    if name == "create_tunnel":
        target      = arguments["target"]
        local_port  = arguments["local_port"]
        r_target    = arguments["remote_target"]
        r_port      = arguments["remote_port"]

        row_id = state.add_pivot(
            pivot_type="tunnel",
            target=target,
            local_port=local_port,
            remote_target=r_target,
            remote_port=r_port,
        )
        msg = (
            f"Tunnel recorded (id={row_id}): "
            f"localhost:{local_port} → {target} → {r_target}:{r_port}\n"
            f"Command: ssh -L {local_port}:{r_target}:{r_port} user@{target} -N"
        )
        return [types.TextContent(type="text", text=msg)]

    elif name == "start_socks_proxy":
        target     = arguments["target"]
        local_port = arguments["local_port"]

        row_id = state.add_pivot(
            pivot_type="socks",
            target=target,
            local_port=local_port,
        )
        msg = (
            f"SOCKS5 proxy recorded (id={row_id}): "
            f"localhost:{local_port} → {target}\n"
            f"Command: ssh -D {local_port} user@{target} -N\n"
            f"Use with: proxychains4 or export ALL_PROXY=socks5://127.0.0.1:{local_port}"
        )
        return [types.TextContent(type="text", text=msg)]

    elif name == "list_pivots":
        pivots = state.list_pivots()
        if not pivots:
            return [types.TextContent(type="text", text="No pivot sessions recorded for the active engagement.")]
        return [types.TextContent(type="text", text=json.dumps(pivots, indent=2, default=str))]

    return []


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-pivot",
                server_version="0.2.0",
                capabilities=server.get_capabilities(),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
