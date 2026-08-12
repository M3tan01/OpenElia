import asyncio
import os
import sys
import httpx
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

def _validate_webhook_url(url: str) -> str:
    """
    Validate webhook URL against the SIEM_WEBHOOK_ALLOWLIST hostname allowlist.
    Thin wrapper around core.webhook.validate_webhook_url — kept as a
    module-level name so tests can patch it directly.
    """
    from core.webhook import validate_webhook_url
    return validate_webhook_url(url, "SIEM_WEBHOOK_ALLOWLIST")

def _audit_log_path() -> str:
    """Return the canonical path to state/audit.log, honouring OPENELIA_STATE_DIR."""
    return os.path.join(os.getenv("OPENELIA_STATE_DIR", "state"), "audit.log")


# Ensure we can import security_manager / core
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from security_manager import PrivacyGuard
from core.jsonl import tail_jsonl

server = Server("mcp-siem")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="forward_event",
            description="Forward a single security event to an external SIEM webhook.",
            inputSchema={
                "type": "object",
                "properties": {
                    "webhook_url": {"type": "string", "description": "The SIEM listener URL"},
                    "payload": {"type": "object", "description": "The event JSON data"},
                },
                "required": ["webhook_url", "payload"],
            },
        ),
        types.Tool(
            name="sync_audit_log",
            description="Sync the entire local audit log to a remote SIEM endpoint.",
            inputSchema={
                "type": "object",
                "properties": {
                    "webhook_url": {"type": "string"},
                    "limit": {"type": "integer", "default": 100},
                },
                "required": ["webhook_url"],
            },
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    async with httpx.AsyncClient() as client:
        if name == "forward_event":
            try:
                url = _validate_webhook_url(arguments["webhook_url"])
            except ValueError as e:
                return [types.TextContent(type="text", text=f"SSRF Guard: {e}")]
            # Tier 4: Outbound PII Redaction
            payload = PrivacyGuard.redact(arguments["payload"])
            try:
                response = await client.post(url, json=payload, timeout=5)
                response.raise_for_status()
                return [types.TextContent(type="text", text=f"SUCCESS: Event forwarded to {url} [{response.status_code}]")]
            except Exception as e:
                return [types.TextContent(type="text", text=f"SIEM Forward Error: {str(e)}")]

        elif name == "sync_audit_log":
            try:
                validated_url = _validate_webhook_url(arguments["webhook_url"])
            except ValueError as e:
                return [types.TextContent(type="text", text=f"SSRF Guard: {e}")]

            limit = int(arguments.get("limit", 100))
            log_path = _audit_log_path()

            if not os.path.exists(log_path):
                return [types.TextContent(
                    type="text",
                    text=f"SIEM Sync: no audit log found at {log_path}; nothing to forward.",
                )]

            # File read, parse, redaction, and POST all share one error scope so
            # any OSError / decode error / redact failure returns a safe string
            # rather than escaping the MCP dispatch as an uncaught exception.
            try:
                events = tail_jsonl(log_path, limit)
                redacted_events = [PrivacyGuard.redact(event) for event in events]
                payload = {"events": redacted_events, "count": len(redacted_events)}

                response = await client.post(validated_url, json=payload, timeout=5)
                response.raise_for_status()
                return [types.TextContent(
                    type="text",
                    text=f"SUCCESS: Synchronized {len(redacted_events)} audit entries to {validated_url} [{response.status_code}]",
                )]
            except Exception as e:
                # Emit the exception TYPE only — the validated URL is in scope and
                # str(e) could echo the internal SIEM endpoint.
                return [types.TextContent(type="text", text=f"SIEM Sync Error: {type(e).__name__}")]

    return []

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-siem",
                server_version="0.1.0",
                capabilities=server.get_capabilities(),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
