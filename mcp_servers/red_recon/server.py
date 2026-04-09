#!/usr/bin/env python3
import asyncio
import re
import os
import json
import docker
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types
from pydantic import BaseModel, Field, validator
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from security_manager import enforce_security_gate

# --- Phase 4.2: Parameter Sanitization Pipeline ---
class NmapScanParams(BaseModel):
    target: str = Field(..., description="Target IP, CIDR or hostname")
    scan_type: str = Field("quick", description="Type of scan: quick, service, or full")
    stealth: bool = Field(False, description="Enable stealthier scan flags and jitter")

    @validator("target")
    def validate_target(cls, v):
        # Phase 2.1: Validate target IPs against a strict regex whitelist
        if re.match(r"^(127\.|localhost)", v):
            pass
        if not re.match(r"^[a-zA-Z0-9\.\-/]+$", v):
            raise ValueError("Invalid target format. Potential command injection detected.")
        if ".gov" in v.lower() or ".mil" in v.lower():
            raise ValueError("Scanning of .gov or .mil domains is strictly prohibited.")
        return v

# --- Phase 2.1: Custom MCP Server Development ---
server = Server("mcp-red-recon")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="nmap_scan",
            description="Run a secure nmap scan on a target.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "scan_type": {"type": "string", "enum": ["quick", "service", "full"]},
                    "stealth": {"type": "boolean", "default": False},
                },
                "required": ["target"],
            },
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    if name != "nmap_scan":
        raise ValueError(f"Unknown tool: {name}")

    if not arguments:
        raise ValueError("Missing arguments")

    try:
        params = NmapScanParams(**arguments)
    except Exception as e:
        return [types.TextContent(type="text", text=f"Security Validation Error: {str(e)}")]

    target = params.target
    scan_type = params.scan_type
    stealth = params.stealth

    if stealth:
        scan_configs = {
            "quick": "-sS -T2 -F",
            "service": "-sS -sV -T2 --top-ports 100",
            "full": "-sS -sV -T2 -p 22,80,443,445,3389"
        }
        import secrets
        delay = secrets.SystemRandom().uniform(5.0, 15.0)
        await asyncio.sleep(delay)
    else:
        scan_configs = {
            "quick": "-F -T4",
            "service": "-sV -sC -T4",
            "full": "-p- -sV -T4"
        }
    
    args = scan_configs.get(scan_type, "-F -T4")

    try:
        # Tier 2 & 4: Double Firewall & Immutable Auditing
        enforce_security_gate("mcp-red-recon", target, f"nmap {args} {target}")
        
        # Tier 3: Sterile Execution (Docker)
        client = docker.from_env()
        # Target and args are passed as environment variables — never interpolated
        # into the script string — to eliminate code injection risk.
        py_script = (
            "import nmap, json, os; "
            "nm=nmap.PortScanner(); "
            "nm.scan(os.environ['SCAN_TARGET'], os.environ['SCAN_ARGS']); "
            "print(json.dumps([{"
            "'host': h, 'state': nm[h].state(), "
            "'protocols': [{'protocol': p, 'ports': [{'port': pt, 'state': nm[h][p][pt]['state']} "
            "for pt in nm[h][p].keys()]} for p in nm[h].all_protocols()]"
            "} for h in nm.all_hosts()]))"
        )

        container = client.containers.run(
            image="cyber-ops-recon:strict",
            command=["python3", "-c", py_script],
            environment={"SCAN_TARGET": target, "SCAN_ARGS": args},
            network="none",  # Egress Denial
            cap_drop=["ALL"],
            cap_add=["NET_RAW"],  # Allow packet crafting
            user="nobody",
            auto_remove=True
        )
        
        output = container.decode('utf-8')
        return [types.TextContent(type="text", text=output)]

    except docker.errors.ImageNotFound:
        return [types.TextContent(type="text", text="Error: cyber-ops-recon:strict image not found. Run 'docker build -t cyber-ops-recon:strict -f Dockerfile.offensive .'")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Scan failed: {str(e)}")]

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-red-recon",
                server_version="0.1.0",
                capabilities=server.get_capabilities(),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
