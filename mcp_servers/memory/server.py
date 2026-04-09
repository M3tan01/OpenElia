#!/usr/bin/env python3
import asyncio
import json
import os
import sys
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

# Ensure we can import VectorManager
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from vector_manager import VectorManager

server = Server("mcp-memory")
vm = VectorManager()

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="search_memory",
            description="Search historical engagement logs and tool outputs using semantic search.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The search query (e.g. 'findings on port 445')"},
                    "limit": {"type": "integer", "default": 5},
                },
                "required": ["query"],
            },
        ),
        types.Tool(
            name="index_event",
            description="Index a new event or tool output into the vectorized memory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "event_type": {"type": "string"},
                    "content": {"type": "string"},
                    "metadata": {"type": "object"},
                },
                "required": ["source", "event_type", "content"],
            },
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    if name == "search_memory":
        query = arguments["query"]
        limit = arguments.get("limit", 5)
        results = vm.search(query, limit)
        return [types.TextContent(type="text", text=json.dumps(results, indent=2))]
    
    elif name == "index_event":
        vm.index_event(arguments["source"], arguments["event_type"], arguments["content"], arguments.get("metadata"))
        return [types.TextContent(type="text", text="Event indexed successfully.")]

    return []

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-memory",
                server_version="0.1.0",
                capabilities=server.get_capabilities(),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
