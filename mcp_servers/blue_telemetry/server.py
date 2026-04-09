#!/usr/bin/env python3
import asyncio
import json
import os
from datetime import datetime
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

# --- Phase 2.3: Defensive Sub-Agents (Blue Team) ---
# This server acts as a standardized telemetry aggregator
server = Server("mcp-blue-telemetry")

LOG_FILE = "state/blue_telemetry.json"

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available telemetry tools."""
    return [
        types.Tool(
            name="log_security_event",
            description="Log a standardized security event (e.g., from a Red Team scan).",
            inputSchema={
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "The tool/agent that generated the event"},
                    "event_type": {"type": "string", "enum": ["recon", "exploit", "access", "exfil"]},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "details": {"type": "object", "description": "Arbitrary event data"},
                },
                "required": ["source", "event_type", "severity", "details"],
            },
        ),
        types.Tool(
            name="read_alerts",
            description="Read the latest security alerts from the telemetry log.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 10},
                },
            },
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle telemetry tool calls."""
    if name == "log_security_event":
        if not arguments:
            raise ValueError("Missing arguments")
            
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": arguments["source"],
            "event_type": arguments["event_type"],
            "severity": arguments["severity"],
            "details": arguments["details"],
        }
        
        # Phase 2.3: Writes a standardized JSON event log simulating an SIEM alert.
        try:
            os.makedirs("state", exist_ok=True)
            events = []
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    try:
                        events = json.load(f)
                    except:
                        events = []
            
            events.append(event)
            with open(LOG_FILE, "w") as f:
                json.dump(events, f, indent=2)
                
            return [types.TextContent(type="text", text=f"Event logged successfully: {event['event_type']} from {event['source']}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Failed to log event: {str(e)}")]

    elif name == "read_alerts":
        limit = (arguments or {}).get("limit", 10)
        try:
            if not os.path.exists(LOG_FILE):
                return [types.TextContent(type="text", text="No alerts found.")]
                
            with open(LOG_FILE, "r") as f:
                events = json.load(f)
                latest = events[-limit:]
                return [types.TextContent(type="text", text=json.dumps(latest, indent=2))]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Failed to read alerts: {str(e)}")]

    return []

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-blue-telemetry",
                server_version="0.1.0",
                capabilities=server.get_capabilities(),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
