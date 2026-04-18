#!/usr/bin/env python3
import asyncio
import json
import httpx
import os
import sys
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

# Ensure we can import SecretStore
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from secret_store import SecretStore

server = Server("mcp-threat-intel")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="lookup_cve",
            description="Lookup details for a specific CVE ID using Circl.lu API.",
            inputSchema={"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
        ),
        types.Tool(
            name="query_shodan",
            description="Search Shodan for information about a specific IP address.",
            inputSchema={"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
        ),
        types.Tool(
            name="query_virustotal",
            description="Check VirusTotal for information about a file hash, domain, or IP.",
            inputSchema={
                "type": "object", 
                "properties": {
                    "resource": {"type": "string", "description": "The SHA256 hash, IP, or domain to check"}
                }, 
                "required": ["resource"]
            },
        ),
        types.Tool(
            name="query_graynoise",
            description="Check if an IP address is known internet noise or a targeted threat.",
            inputSchema={"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
        ),
        types.Tool(
            name="search_exploits",
            description="Search for publicly available exploits for a service or CVE.",
            inputSchema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        if name == "lookup_cve":
            cve_id = arguments["cve_id"]
            try:
                response = await client.get(f"https://cve.circl.lu/api/cve/{cve_id}")
                return [types.TextContent(type="text", text=json.dumps(response.json(), indent=2))]
            except Exception as e:
                return [types.TextContent(type="text", text=f"CVE error: {str(e)}")]

        elif name == "query_shodan":
            ip = arguments["ip"]
            api_key = SecretStore.get_secret("SHODAN_API_KEY")
            if not api_key: return [types.TextContent(type="text", text="Error: Shodan key missing.")]
            try:
                response = await client.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": api_key})
                return [types.TextContent(type="text", text=json.dumps(response.json(), indent=2))]
            except Exception as e:
                return [types.TextContent(type="text", text=f"Shodan error: {str(e)}")]

        elif name == "query_virustotal":
            resource = arguments["resource"]
            api_key = SecretStore.get_secret("VT_API_KEY")
            if not api_key: return [types.TextContent(type="text", text="Error: VT key missing.")]
            try:
                headers = {"x-apikey": api_key}
                # Check if it's an IP, domain, or hash (simplified)
                response = await client.get(f"https://www.virustotal.com/api/v3/search?query={resource}", headers=headers)
                return [types.TextContent(type="text", text=json.dumps(response.json(), indent=2))]
            except Exception as e:
                return [types.TextContent(type="text", text=f"VirusTotal error: {str(e)}")]

        elif name == "query_graynoise":
            ip = arguments["ip"]
            api_key = SecretStore.get_secret("GRAYNOISE_API_KEY")
            if not api_key: return [types.TextContent(type="text", text="Error: GrayNoise key missing.")]
            try:
                headers = {"key": api_key}
                response = await client.get(f"https://api.graynoise.io/v3/community/{ip}", headers=headers)
                return [types.TextContent(type="text", text=json.dumps(response.json(), indent=2))]
            except Exception as e:
                return [types.TextContent(type="text", text=f"GrayNoise error: {str(e)}")]

        elif name == "search_exploits":
            return [types.TextContent(type="text", text="Simulated exploit search.")]

    return []

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-threat-intel",
                server_version="0.1.0",
                capabilities=server.get_capabilities(),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
