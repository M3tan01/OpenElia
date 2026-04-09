# Changelog

All notable changes to the OpenElia project will be documented in this file.

## [1.0.1] - 2026-04-08

### 🔒 Security Hardening

- **Vault encryption**: Credentials are now encrypted at rest using Fernet AES-256 (`state/vault.bin`). The encryption key lives exclusively in the OS keyring. Automatic one-time migration from any legacy plaintext `state/vault.json`.
- **SSRF prevention**: SIEM webhook URLs are now validated against a strict hostname allowlist (`SIEM_WEBHOOK_ALLOWLIST` env var). Unknown or private hostnames are denied by default, replacing the previous blocklist approach.
- **Code injection fix**: Nmap target and args in `mcp-red-recon` are passed as Docker environment variables, never interpolated into the Python script string.
- **Command injection fix**: Metasploit commands in `cmd_msf` are written to a temp resource file (`-r`) instead of injected via the `-x` CLI flag. Target is validated with `ipaddress` before use.
- **Input validation**: Nmap targets validated via `ipaddress.ip_network()` / `ip_address()`. Args stripped of shell metacharacters (`;`, `|`, `` ` ``, `$`, etc.).
- **Shodan key protection**: API key moved from URL query string (logged by proxies/servers) to `params={}` dict.
- **Fail-closed RoE**: `ScopeValidator` now blocks all targets when `roe.json` is missing or `authorized_subnets` is empty. Previously defaulted to allow-all.
- **HMAC audit chain**: Every audit log entry now carries a `_chain` field — HMAC-SHA256 over `(prev_chain + event_json)`. Tampering with any entry breaks the chain.
- **HMAC IdP sessions**: `state/idp_session.json` is now validated against an HMAC-SHA256 signature. Unsigned or tampered session files are rejected.
- **Secure file permissions**: Artifacts, vault, and forensic DB are written with `chmod 0o600` (owner read/write only).
- **Secret access logging**: Every `SecretStore.get_secret()` call emits a structured audit log line with the key name and source (`keyring`/`env`/`missing`) — never the value.
- **Prompt injection mitigation**: All tool results are wrapped in inert delimiters, matched against known injection patterns, and capped at 8,000 chars before re-entering the model context.
- **Undefined function fix**: `_get_secret()` call in `cmd_msf` replaced with `SecretStore.get_secret()`.
- **Docker network hardening**: `cmd_msf` container changed from `network_mode="host"` to `network="bridge"`.
- **Safe JSON deserialization**: All `json.loads()` calls on DB-stored data replaced with `_safe_json_loads()` which enforces a 5 MB size cap.
- **Dependency**: Added `cryptography>=42.0` to `requirements.txt`.

## [1.0.0-Gold] - 2026-04-08

### 🚀 Added
- **Autonomous Purple Team Loop**: Collaborative attack/defend simulation with "Continuous Chaos" iterative logic.
- **Interactive War Room Dashboard**: Live-updating TUI using `rich` with an integrated command center.
- **Shadow Shell (Interactive Handoff)**: A new tool allowing AI agents to hand over live sessions to human operators.
- **5-Tier Security Architecture**:
    - Tier 1: Hardware-backed Secret Store (OS Keyring).
    - Tier 2: Double Firewall (Mathematical Scope & Semantic Payload Sanitization).
    - Tier 3: Sterile Execution (Rootless Ephemeral Docker Containers).
    - Tier 4: Immutable Auditing (Fail-closed JSON audit log).
    - Tier 5: Supply Chain Integrity (Hash-locked dependencies & SBOM).
- **Intelligence & Memory**:
    - **Attack Surface Knowledge Graph**: Relationship mapping via `NetworkX`.
    - **Vector Engagement Memory**: Long-term semantic search via `ChromaDB`.
    - **Atomic Red Team**: Integrated library of research-backed offensive techniques.
- **Enterprise Features**: External SIEM forwarding and automated SBOM generation.
- **Governance**: MIT License and community contribution guidelines.

### 🛡️ Changed
- **Branding**: Complete transition from CyberArb-Framework to **OpenElia**.
- **Persistence**: Migrated from flat JSON state to a multi-target **SQLite relational backend**.
- **Standardization**: Full alignment with **Python 3.11+** industry standards.
- **Privacy**: Integrated a **Privacy Guard** middleware for automatic outbound PII redaction.

### 🧹 Removed
- Legacy JSON state files and redundant test scripts.
- Proprietary source code dependencies.
