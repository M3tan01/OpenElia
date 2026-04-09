#!/usr/bin/env python3
import asyncio
import json
import os
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

server = Server("mcp-pivot")

PIVOT_FILE = "state/pivots.json"

def load_pivots():
    os.makedirs("state", exist_ok=True)
    if not os.path.exists(PIVOT_FILE):
        return []
    try:
        with open(PIVOT_FILE, "r") as f:
            return json.load(f)
    except:
        return []

def save_pivots(data):
    os.makedirs("state", exist_ok=True)
    with open(PIVOT_FILE, "w") as f:
        json.dump(data, f, indent=2)

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available pivot tools."""
    return [
        types.Tool(
            name="create_tunnel",
            description="Create a secure SSH tunnel to a compromised host.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The compromised host to pivot through"},
                    "local_port": {"type": "integer", "description": "The local port to listen on"},
                    "remote_target": {"type": "string", "description": "The destination host inside the target's network"},
                    "remote_port": {"type": "integer", "description": "The destination port"},
                },
                "required": ["target", "local_port", "remote_target", "remote_port"],
            },
        ),
        types.Tool(
            name="start_socks_proxy",
            description="Start a SOCKS5 proxy on a local port through a compromised host.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The compromised host to pivot through"},
                    "local_port": {"type": "integer", "description": "The local port to listen on (e.g. 9050)"},
                },
                "required": ["target", "local_port"],
            },
        ),
        types.Tool(
            name="list_pivots",
            description="List all active tunnels and proxies managed by the framework.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    pivots = load_pivots()

    if name == "create_tunnel":
        if not arguments:
            raise ValueError("Missing arguments")
        
        pivot = {
            "type": "tunnel",
            "target": arguments["target"],
            "local_port": arguments["local_port"],
            "remote_target": arguments["remote_target"],
            "remote_port": arguments["remote_port"],
            "status": "active" # Simulation
        }
        
        pivots.append(pivot)
        save_pivots(pivots)
        
        return [types.TextContent(type="text", text=f"SSH Tunnel created: localhost:{pivot['local_port']} -> {pivot['target']} -> {pivot['remote_target']}:{pivot['remote_port']}")]

    elif name == "start_socks_proxy":
        if not arguments:
            raise ValueError("Missing arguments")
            
        pivot = {
            "type": "socks",
            "target": arguments["target"],
            "local_port": arguments["local_port"],
            "status": "active" # Simulation
        }
        
        pivots.append(pivot)
        save_pivots(pivots)
        
        return [types.TextContent(type="text", text=f"SOCKS5 Proxy started on port {pivot['local_port']} through {pivot['target']}. Use with proxychains or similar.")]

    elif name == "list_pivots":
        if not pivots:
            return [types.TextContent(type="text", text="No active pivots found.")]
        return [types.TextContent(type="text", text=json.dumps(pivots, indent=2))]

    return []

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-pivot",
                server_version="0.1.0",
                capabilities=server.get_capabilities(),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
