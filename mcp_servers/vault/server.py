#!/usr/bin/env python3
import asyncio
import json
import os
import sys
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types
from cryptography.fernet import Fernet, InvalidToken

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from secret_store import SecretStore

server = Server("mcp-vault")

VAULT_FILE = "state/vault.bin"
_VAULT_KEY_NAME = "VAULT_ENCRYPTION_KEY"


def _get_fernet() -> Fernet:
    key = SecretStore.get_secret(_VAULT_KEY_NAME)
    if not key:
        key = Fernet.generate_key().decode()
        SecretStore.set_secret(_VAULT_KEY_NAME, key)
    raw = key.encode() if isinstance(key, str) else key
    return Fernet(raw)


_LEGACY_VAULT_FILE = "state/vault.json"


def _migrate_legacy_vault() -> None:
    """One-time migration: encrypt state/vault.json → state/vault.bin, then delete the plaintext file."""
    if not os.path.exists(_LEGACY_VAULT_FILE):
        return
    if os.path.exists(VAULT_FILE):
        # Encrypted vault already exists — just remove the legacy plaintext file
        try:
            os.unlink(_LEGACY_VAULT_FILE)
        except OSError:
            pass
        return
    try:
        with open(_LEGACY_VAULT_FILE, "r") as f:
            data = json.load(f)
        save_vault(data)
        os.unlink(_LEGACY_VAULT_FILE)
    except Exception:
        pass  # Leave legacy file in place if migration fails; do not crash


def load_vault() -> dict:
    os.makedirs("state", exist_ok=True)
    _migrate_legacy_vault()
    if not os.path.exists(VAULT_FILE):
        return {}
    try:
        with open(VAULT_FILE, "rb") as f:
            encrypted = f.read()
        if not encrypted:
            return {}
        return json.loads(_get_fernet().decrypt(encrypted))
    except (InvalidToken, json.JSONDecodeError):
        return {}


def save_vault(data: dict) -> None:
    os.makedirs("state", exist_ok=True)
    encrypted = _get_fernet().encrypt(json.dumps(data).encode())
    # Atomic write with strict permissions (owner read/write only)
    fd = os.open(VAULT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(encrypted)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available vault tools."""
    return [
        types.Tool(
            name="store_credential",
            description="Store a credential secret in the secure vault securely.",
            inputSchema={
                "type": "object",
                "properties": {
                    "alias": {"type": "string", "description": "The alias to reference this credential later (e.g. 'Target-Admin')"},
                    "secret": {"type": "string", "description": "The actual secret (password, hash, API key)"},
                },
                "required": ["alias", "secret"],
            },
        ),
        types.Tool(
            name="list_aliases",
            description="List all available credential aliases. The LLM cannot view the secrets, only the aliases.",
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
    if name == "store_credential":
        if not arguments:
            raise ValueError("Missing arguments")
        alias = arguments["alias"]
        secret = arguments["secret"]
        
        vault_data = load_vault()
        vault_data[alias] = secret
        save_vault(vault_data)
        
        return [types.TextContent(type="text", text=f"Credential stored securely under alias '{alias}'.")]

    elif name == "list_aliases":
        vault_data = load_vault()
        aliases = list(vault_data.keys())
        if not aliases:
            return [types.TextContent(type="text", text="No credentials stored in the vault.")]
        return [types.TextContent(type="text", text=f"Available credential aliases: {', '.join(aliases)}")]

    return []

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-vault",
                server_version="0.1.0",
                capabilities=server.get_capabilities(),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
