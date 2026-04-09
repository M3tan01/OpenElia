# Contributing to OpenElia

First off, thank you for considering contributing to OpenElia! It's people like you that make this an industry-standard tool for autonomous security.

## 🚀 How Can I Contribute?

### 1. Adding New Atomic Tests
If you have a research-backed offensive technique, add it to `skills/atomic/definitions.json`. Ensure you include the MITRE TTP ID and exact commands for Windows/Linux.

### 2. Building Custom MCP Servers
We are always looking for new "Hands" for the framework. If you build a new MCP server (e.g., for a specific EDR or Firewall), place it in `mcp_servers/` and update the `.mcp.json` template.

### 3. Improving Agent Intelligence
You can tune the system prompts in `agents/red/` or `agents/blue/` to make the agents more surgical or stealthy.

## 🛡️ Security Guidelines

*   **NEVER** commit API keys or real engagement data. Use `./scrub.py` before every push.
*   All offensive techniques must be authorized and systematic.
*   Every new tool execution path must pass through `enforce_security_gate` in `security_manager.py`.
*   `roe.json` must define `authorized_subnets`. The scope validator is **fail-closed** — missing or empty subnets block all operations.
*   New subprocess or Docker calls must use list-form commands (never `shell=True`) and validate all user-supplied inputs with `ipaddress` or an explicit allowlist before use.
*   External data (API responses, scan output, log content) must be treated as untrusted. Use `BaseAgent._sanitize_tool_result()` before feeding external data back to any LLM context.
*   Secrets must go through `SecretStore`. Never read from `os.environ` directly for sensitive values.
*   New files containing sensitive data must be created with `os.open(..., 0o600)` — never with `open()` alone.
*   New outbound HTTP calls to user-supplied URLs require SSRF protection: use an explicit hostname allowlist, not a blocklist.

## 🏗️ Development Setup

1.  Run `./setup.sh` to initialize the environment.
2.  Build the sterile container: `docker build -t cyber-ops-recon:strict -f Dockerfile.offensive .`
3.  Configure `roe.json` with your lab's `authorized_subnets`.
4.  Set `SIEM_WEBHOOK_ALLOWLIST` if testing SIEM forwarding.
5.  Verify your changes with `python main.py check`.

## 📜 Code of Conduct
Be professional, be respectful, and always operate with high integrity. This is a tool for defenders and ethical researchers.
