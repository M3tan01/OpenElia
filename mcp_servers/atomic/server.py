#!/usr/bin/env python3
import asyncio
import json
import os
import sys
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

# Ensure we can import AtomicManager
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from atomic_manager import AtomicManager

server = Server("mcp-atomic")
am = AtomicManager()

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="list_atomic_ttps",
            description="List all MITRE TTPs supported by the local Atomic Red Team library.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_atomic_test",
            description="Retrieve the exact command and details for a specific Atomic Red Team test.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ttp_id": {"type": "string", "description": "e.g. 'T1053.005'"},
                    "test_id": {"type": "integer", "default": 1},
                },
                "required": ["ttp_id"],
            },
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    if name == "list_atomic_ttps":
        ttps = am.list_ttps()
        return [types.TextContent(type="text", text=json.dumps(ttps, indent=2))]
    
    elif name == "get_atomic_test":
        ttp_id = arguments["ttp_id"]
        test_id = arguments.get("test_id", 1)
        test = am.get_test(ttp_id, test_id)
        if test:
            return [types.TextContent(type="text", text=json.dumps(test, indent=2))]
        else:
            return [types.TextContent(type="text", text=f"Error: TTP {ttp_id} (Test {test_id}) not found in Atomic library.")]

    return []

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-atomic",
                server_version="0.1.0",
                capabilities=server.get_capabilities(),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
