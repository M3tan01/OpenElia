#!/usr/bin/env python3
import asyncio
import json
import os
import sys
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

# Ensure we can import GraphManager
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from graph_manager import GraphManager

server = Server("mcp-graph")
gm = GraphManager()

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="add_host",
            description="Add a host node to the attack surface graph.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "hostname": {"type": "string"},
                    "os": {"type": "string"},
                },
                "required": ["ip"],
            },
        ),
        types.Tool(
            name="add_service",
            description="Add a service node and link it to a host.",
            inputSchema={
                "type": "object",
                "properties": {
                    "host_ip": {"type": "string"},
                    "port": {"type": "integer"},
                    "protocol": {"type": "string", "enum": ["tcp", "udp"]},
                    "service_name": {"type": "string"},
                    "version": {"type": "string"},
                },
                "required": ["host_ip", "port", "protocol", "service_name"],
            },
        ),
        types.Tool(
            name="add_vulnerability",
            description="Add a vulnerability node and link it to a service.",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_id": {"type": "string", "description": "e.g. '10.0.0.1:80/tcp'"},
                    "cve_id": {"type": "string"},
                    "severity": {"type": "string"},
                    "description": {"type": "string"},
                },
                "required": ["service_id", "cve_id", "severity"],
            },
        ),
        types.Tool(
            name="find_attack_paths",
            description="Find all simple paths between two nodes in the graph.",
            inputSchema={
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "target": {"type": "string"},
                },
                "required": ["source", "target"],
            },
        ),
        types.Tool(
            name="get_graph_summary",
            description="Get a summary of the current attack surface graph.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="export_graph",
            description="Export the attack surface graph to Mermaid.js format for visualization.",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_mitre_heatmap",
            description="Calculate MITRE ATT&CK coverage heatmap based on current findings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {"type": "object"}
                    }
                },
                "required": ["findings"],
            },
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    if name == "add_host":
        gm.add_host(arguments["ip"], arguments.get("hostname"), arguments.get("os"))
        return [types.TextContent(type="text", text=f"Host {arguments['ip']} added to graph.")]
    
    elif name == "add_service":
        gm.add_service(arguments["host_ip"], arguments["port"], arguments["protocol"], arguments["service_name"], arguments.get("version"))
        return [types.TextContent(type="text", text=f"Service {arguments['service_name']} added to {arguments['host_ip']}.")]

    elif name == "add_vulnerability":
        gm.add_vulnerability(arguments["service_id"], arguments["cve_id"], arguments["severity"], arguments.get("description"))
        return [types.TextContent(type="text", text=f"Vulnerability {arguments['cve_id']} linked to {arguments['service_id']}.")]

    elif name == "find_attack_paths":
        paths = gm.find_paths(arguments["source"], arguments["target"])
        return [types.TextContent(type="text", text=json.dumps(paths, indent=2))]

    elif name == "get_graph_summary":
        summary = gm.get_summary()
        return [types.TextContent(type="text", text=json.dumps(summary, indent=2))]

    elif name == "export_graph":
        mermaid_code = gm.export_to_mermaid()
        return [types.TextContent(type="text", text=f"Mermaid.js Attack Surface Graph:\n\n```mermaid\n{mermaid_code}\n```")]

    elif name == "get_mitre_heatmap":
        heatmap = gm.get_mitre_heatmap(arguments["findings"])
        return [types.TextContent(type="text", text=json.dumps(heatmap, indent=2))]

    return []

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-graph",
                server_version="0.1.0",
                capabilities=server.get_capabilities(),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
