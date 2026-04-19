#!/usr/bin/env python3
"""
mcp_servers/blue_remediate/server.py — Automated remediation MCP server.

Operates in two modes controlled by the BLUE_REMEDIATE_LIVE environment variable:

  BLUE_REMEDIATE_LIVE=0 (default) — SIMULATION MODE
    All actions are dry-run stubs. No real system changes are made.
    Safe to run in any environment. Logs the real command that *would* execute.

  BLUE_REMEDIATE_LIVE=1 — LIVE MODE
    Executes real system calls (iptables, kill).
    ⚠️  Requirements before enabling:
      • Store BLUE_REMEDIATE_RBAC_TOKEN in the keychain via SecretStore.bootstrap().
      • Run as a user with iptables privileges (root or CAP_NET_ADMIN).
      • Tested only on Linux. macOS/Windows will fall back to simulation.
"""
import asyncio
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from mcp.server.models import InitializationOptions
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

# ---------------------------------------------------------------------------
# Mode detection
# ---------------------------------------------------------------------------
_LIVE_MODE: bool = os.environ.get("BLUE_REMEDIATE_LIVE", "0").strip() == "1"
_SIM_TAG = "[SIMULATION — no real action taken]"
_LIVE_TAG = "[LIVE — real system action executed]"

# ---------------------------------------------------------------------------
# RBAC gate
# ---------------------------------------------------------------------------
def _check_rbac() -> tuple[bool, str]:
    """Return (authorised, reason). Validates the RBAC token from the keychain."""
    try:
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
        from secret_store import SecretStore
        token = (SecretStore.get_secret("BLUE_REMEDIATE_RBAC_TOKEN") or "").strip()
        if token:
            return True, "RBAC token verified."
        return False, "BLUE_REMEDIATE_RBAC_TOKEN is not set in the keychain. Run SecretStore.bootstrap() to configure it."
    except Exception as e:
        return False, f"RBAC check failed: {e}"


# ---------------------------------------------------------------------------
# Live action helpers
# ---------------------------------------------------------------------------
def _live_block_ip(ip: str) -> tuple[bool, str]:
    """Insert an iptables DROP rule for the given IP. Linux only."""
    if sys.platform != "linux":
        return False, f"Live block_ip is only supported on Linux (current: {sys.platform})."
    iptables = shutil.which("iptables")
    if not iptables:
        return False, "iptables executable not found in PATH."
    try:
        result = subprocess.run(
            [iptables, "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10
        )  # nosec: B603 — ip is validated by caller
        if result.returncode == 0:
            return True, f"iptables rule inserted: -I INPUT -s {ip} -j DROP"
        return False, f"iptables exited {result.returncode}: {result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return False, "iptables command timed out."
    except Exception as e:
        return False, f"Execution error: {e}"


def _validate_ip(ip: str) -> bool:
    """Reject obviously invalid IP strings before passing to iptables."""
    import re
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?", ip))


def _live_kill_process(pid: int) -> tuple[bool, str]:
    """Send SIGKILL to the given PID."""
    try:
        result = subprocess.run(
            ["kill", "-9", str(pid)],
            capture_output=True, text=True, timeout=5
        )  # nosec: B603 — pid is an integer, not user-controlled string
        if result.returncode == 0:
            return True, f"SIGKILL sent to PID {pid}."
        return False, f"kill exited {result.returncode}: {result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return False, "kill command timed out."
    except Exception as e:
        return False, f"Execution error: {e}"


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------
server = Server("mcp-blue-remediate")


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    mode_note = "LIVE MODE ACTIVE" if _LIVE_MODE else _SIM_TAG
    return [
        types.Tool(
            name="block_ip",
            description=f"Block a malicious IP via iptables DROP rule. {mode_note}",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip":     {"type": "string", "description": "IPv4 address or CIDR to block"},
                    "reason": {"type": "string", "description": "Reason for blocking"},
                },
                "required": ["ip"],
            },
        ),
        types.Tool(
            name="kill_process",
            description=f"Terminate a suspicious process by PID via SIGKILL. {mode_note}",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid":    {"type": "integer", "description": "Process ID to terminate"},
                    "reason": {"type": "string",  "description": "Reason for termination"},
                },
                "required": ["pid"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    ts = datetime.now(timezone.utc).isoformat()
    arguments = arguments or {}

    if name == "block_ip":
        ip     = arguments["ip"]
        reason = arguments.get("reason", "Unknown")

        if not _validate_ip(ip):
            return [types.TextContent(type="text", text=f"ERROR: '{ip}' is not a valid IPv4 address or CIDR.")]

        real_cmd = f"iptables -I INPUT -s {ip} -j DROP"

        if not _LIVE_MODE:
            print(f"[{ts}] {_SIM_TAG} REMEDIATION: block_ip {ip} — {reason}")
            return [types.TextContent(type="text", text=(
                f"{_SIM_TAG}\n"
                f"Action : block_ip\n"
                f"IP     : {ip}\n"
                f"Reason : {reason}\n"
                f"Command: {real_cmd}\n"
                f"To enable live execution: set BLUE_REMEDIATE_LIVE=1 and store BLUE_REMEDIATE_RBAC_TOKEN via SecretStore.bootstrap()."
            ))]

        # Live path — RBAC gate first
        ok, rbac_msg = _check_rbac()
        if not ok:
            print(f"[{ts}] RBAC DENIED block_ip {ip}: {rbac_msg}")
            return [types.TextContent(type="text", text=f"RBAC DENIED: {rbac_msg}")]

        success, detail = _live_block_ip(ip)
        tag = _LIVE_TAG if success else "[LIVE — FAILED]"
        print(f"[{ts}] {tag} block_ip {ip} — {reason} — {detail}")
        return [types.TextContent(type="text", text=(
            f"{tag}\n"
            f"Action : block_ip\n"
            f"IP     : {ip}\n"
            f"Reason : {reason}\n"
            f"Result : {detail}"
        ))]

    elif name == "kill_process":
        pid    = int(arguments["pid"])
        reason = arguments.get("reason", "Suspicious activity")

        real_cmd = f"kill -9 {pid}"

        if not _LIVE_MODE:
            print(f"[{ts}] {_SIM_TAG} REMEDIATION: kill_process PID={pid} — {reason}")
            return [types.TextContent(type="text", text=(
                f"{_SIM_TAG}\n"
                f"Action : kill_process\n"
                f"PID    : {pid}\n"
                f"Reason : {reason}\n"
                f"Command: {real_cmd}\n"
                f"To enable live execution: set BLUE_REMEDIATE_LIVE=1 and store BLUE_REMEDIATE_RBAC_TOKEN via SecretStore.bootstrap()."
            ))]

        # Live path — RBAC gate first
        ok, rbac_msg = _check_rbac()
        if not ok:
            print(f"[{ts}] RBAC DENIED kill_process PID={pid}: {rbac_msg}")
            return [types.TextContent(type="text", text=f"RBAC DENIED: {rbac_msg}")]

        success, detail = _live_kill_process(pid)
        tag = _LIVE_TAG if success else "[LIVE — FAILED]"
        print(f"[{ts}] {tag} kill_process PID={pid} — {reason} — {detail}")
        return [types.TextContent(type="text", text=(
            f"{tag}\n"
            f"Action : kill_process\n"
            f"PID    : {pid}\n"
            f"Reason : {reason}\n"
            f"Result : {detail}"
        ))]

    return []


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcp-blue-remediate",
                server_version="0.2.0",
                capabilities=server.get_capabilities(),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
