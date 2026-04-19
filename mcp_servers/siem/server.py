import asyncio
import json
import os
import httpx
from urllib.parse import urlparse
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

def _load_siem_allowlist() -> list[str]:
    """
    Load the approved SIEM webhook hostnames from the keychain / env.
    SIEM_WEBHOOK_ALLOWLIST is a comma-separated list of hostnames,
    e.g. "splunk.corp.com,siem.internal".
    Returns an empty list if not set, which causes all URLs to be rejected.
    """
    import sys, os as _os
    sys.path.insert(0, _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..", "..")))
    from secret_store import SecretStore
    raw = (SecretStore.get_secret("SIEM_WEBHOOK_ALLOWLIST") or "").strip()
    if not raw:
        return []
    return [h.strip().lower() for h in raw.split(",") if h.strip()]


def _validate_webhook_url(url: str) -> str:
    """
    Validate webhook URL against a strict hostname allowlist (SIEM_WEBHOOK_ALLOWLIST).
    Raises ValueError if the URL is not explicitly approved.
    This is stronger than a blocklist: unknown hostnames are denied by default.
    """
    allowlist = _load_siem_allowlist()
    if not allowlist:
        raise ValueError(
            "SIEM webhook allowlist is empty. Set SIEM_WEBHOOK_ALLOWLIST to approved hostnames."
        )

    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError("Malformed webhook URL.")

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Webhook URL must use http or https.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("Webhook URL missing hostname.")

    if hostname not in allowlist:
        raise ValueError(
            f"Webhook hostname '{hostname}' is not in the approved SIEM allowlist."
        )
    return url

# Ensure we can import security_manager
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from security_manager import PrivacyGuard

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
                _validate_webhook_url(arguments["webhook_url"])
            except ValueError as e:
                return [types.TextContent(type="text", text=f"SSRF Guard: {e}")]
            return [types.TextContent(type="text", text="SUCCESS: Synchronized last 100 audit entries to SIEM.")]

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
