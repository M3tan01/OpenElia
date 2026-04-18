# Changelog

All notable changes to the OpenElia project will be documented in this file.

## [1.0.3] - 2026-04-17

### 🔒 Security Hardening

- **Shell injection fix (MSF)**: `cmd_msf` now passes both target and extra args through `shlex.quote()` before interpolation into the msfconsole `-x` string. Stealth thread-throttling is applied to the raw args before quoting, not via `.replace()` on the final command string.
- **Path traversal fix (AdversaryManager)**: `apt_name` is now validated against a strict `^[a-z0-9_-]{1,32}$` whitelist and the resolved path is checked to be within `adversaries/` before opening.
- **Path traversal fix (ArtifactManager)**: Caller-supplied filenames are sanitised with `Path(filename).name` to strip any directory components before constructing the storage path.
- **Prompt injection hardening**: `_INJECTION_PATTERNS` in `BaseAgent` expanded with XML tag injection (`<system>`, `<instruction>`), Unicode directional overrides, and modern jailbreak prefixes (`DAN:`, `SYSTEM OVERRIDE:`, `sudo mode`, etc.).
- **Keyring persistence guard**: `vault/server.py` and `ArtifactManager` now verify the OS keyring write succeeded immediately after `SecretStore.set_secret()`. A `RuntimeError` is raised if the key cannot be recovered — preventing silent loss of the encryption key.
- **Remediation command allowlist**: `DefenderRes.execute_remediation()` validates every DB-stored command against `_ALLOWED_CMD_PREFIXES` before execution, closing the vector where a tampered DB row could run arbitrary OS commands.
- **Removed `load_dotenv`**: `python-dotenv` is no longer imported or called from `main.py`; removed from `requirements.txt` and `pyproject.toml` direct dependencies.
- **RoE parse error logging**: `ScopeValidator._load_roe()` now logs parse failures to stderr instead of silently swallowing them. Fail-closed behaviour is unchanged.
- **PII pattern expansion**: `PrivacyGuard.PII_PATTERNS` extended with AWS access/secret keys, Bearer tokens, database connection strings, Slack webhooks, Anthropic API keys, and generic `api_key=` patterns.

### 🐛 Bug Fixes

- **`add_response_action()` return value**: `StateManager.add_response_action()` now returns `{"id": cursor.lastrowid}` instead of `None`; callers that used `res.get("id")` now work correctly.
- **Phase validation**: `StateManager.write_agent_result()` raises `ValueError` for unknown phase names, preventing silent writes to non-existent phase rows.
- **Async remediation dispatch**: Removed `asyncio.create_task()` calls from the synchronous `_execute_res_tool()` method in `DefenderRes`. All remediation now requires explicit operator invocation via `python main.py execute-remediation --action-id N`.
- **TheHive secret naming**: `dispatch_thehive_case()` now correctly reads `THEHIVE_URL` and `THEHIVE_API_KEY` as separate keyring entries (previously used `THEHIVE_API_KEY` for the URL).
- **Threshold counters (sliding window)**: `DefenderMon` threshold counters now use a time-based sliding window (`collections.deque` of `time.monotonic()` timestamps) instead of unbounded incrementing integers. Stale events older than `window_seconds` (default 1 hour) are evicted before threshold evaluation.
- **LLM trigger threshold**: `DefenderOS` no longer escalates to the LLM for any log batch over 100 characters. Escalation now requires Tier 1 alerts to have fired.
- **Log sanitisation**: `DefenderOS` passes log text through `BaseAgent._sanitize_tool_result()` before including it in an LLM prompt.

### ✨ Features

- **`execute-remediation` CLI command**: New `python main.py execute-remediation --action-id N` subcommand allows operators to explicitly execute a previously logged and approved response action.
- **`get_escalated_analysis_count()`**: New `StateManager` method returns the count of `blue_analyses` rows with `escalate=1` for the active engagement; used by `DefenderOS` to gate Tier 4 remediation.
- **Mimikatz command detection rule**: Added `T1003_MIMIKATZ_CMD` Sigma rule to `DefenderMon`, detecting `sekurlsa::`, `lsadump::`, `procdump lsass`, and related patterns in plain log text (complements the existing Sysmon EventCode 10 rule).
- **LLM call audit logging**: Every outbound `client.chat.completions.create()` call in `BaseAgent` now emits a structured `LLM_CALL` audit entry with model name and prompt token count.
- **LLM retry with backoff**: `BaseAgent._run_tool_loop()` retries transient LLM API errors up to 3 times with exponential backoff (1 s → 2 s → 4 s, capped at 30 s).
- **Dashboard pivot panel**: War Room TUI now includes a 6th panel showing active pivot sessions from `StateManager.list_pivots()`.
- **Blue remediate live mode**: `mcp-blue-remediate` server supports dual-mode operation — simulation (default) and live execution via `BLUE_REMEDIATE_LIVE=1` with RBAC token verification against the OS keyring.
- **TypeScript CLI `report` command**: Added `openelia-cli report [--task <str>] [--brain-tier <tier>]` to the TypeScript CLI.

### 🧪 Tests

- Added `tests/conftest.py` — ensures the project root is on `sys.path` regardless of pytest invocation directory.
- Added `tests/test_state_manager.py` — 17 tests covering engagement lifecycle, phase validation, `add_response_action` return value, and `get_escalated_analysis_count`.
- Added `tests/test_security.py` — 21 tests covering `PrivacyGuard` (old and new PII patterns), `ScopeValidator`, and `AdversaryManager` path traversal prevention.
- Added `tests/test_defender_mon.py` — 22 tests covering alert structure, LSASS/Mimikatz/ransomware/lateral detection, sliding window threshold behaviour, and edge cases.
- Added `.github/workflows/test.yml` — CI pipeline runs the full test suite on push to `main`/`dev` and on PRs to `main`.

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
