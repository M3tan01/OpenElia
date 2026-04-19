# Changelog

All notable changes to the OpenElia project will be documented in this file.

## [1.0.5] - 2026-04-19

### ✨ Features
- **Iterative Purple Loop**: `cmd_purple` rewritten as a true N-iteration red→blue feedback loop with coverage delta tracking, early exit at 100% coverage, and adaptive red task seeding based on previous blue alert types.
- **`force_domain` Routing**: Added to `orchestrator.py` to skip LLM classifier and drive alternating red/blue/reporter phases cheaply.
- **TS CLI Proxy-Port Wiring**: Added `--proxy-port` option to red and purple commands in TypeScript CLI (`src/src/index.ts`, `src/src/cli.ts`).
- **Vault `retrieve_credential`**: Added to `mcp_servers/vault/server.py` to fetch a secret back out from the vault.

### 🧪 Tests
- **`test_vector_manager.py`**: Added coverage for metadata, search delegation, threshold/exception, cache_response type.
- **`test_atomic_manager.py`**: Added coverage for TTP lookup hit/miss, missing file, executor field, etc.
- **`test_graph_manager.py`**: Added coverage for host/service/vuln/cred, find_paths, neighbors, query_by_type, summary, Mermaid export, MITRE heatmap, persistence.

## [1.0.4] - 2026-04-18

### 🔒 Security Hardening

- **OpenClaw module** (`openclaw/`): Zero-trust external data ingestion boundary. All external payloads pass through two independent gates — Pydantic strict-mode schema validation (`extra="forbid"`, cross-field validators) and a 200+ pattern injection regex (`_INJECTION_RE`) — before any agent can read them. Raw response bodies are discarded after hashing; only SHA-256 digests are retained.
- **SSRF prevention** (`OpenClawConnector._validate_uri`): Blocks cloud metadata endpoints (IMDS, `169.254.169.254`, etc.), all private/loopback/link-local CIDRs, and non-http(s) schemes. HTTP redirects are never followed. Network allowlist (`OPENCLAW_ALLOWED_HOSTS`) is fail-closed — all outbound connections are blocked if the list is empty.
- **Hermetic subprocess** (`OpenClawConnector.run_isolated`): Child processes receive `env={}`, inheriting zero environment variables, eliminating the credential-leakage-via-env-var vector.
- **Ephemeral credential lifecycle** (`OpenClawConnector._ephemeral_token`): Credentials are fetched from SecretStore, used in the narrowest possible scope, then `del + gc.collect()` immediately on context exit.
- **Immutable audit log** (`ClawAuditLog`): HMAC-SHA-256 chained append-only log (`state/openclaw_audit.jsonl`). Every deletion, reordering, or content modification is detectable via `verify_chain()`. Credential-adjacent meta keys (`token`, `password`, `api_key`, etc.) are silently dropped at write time.
- **Bandit B603/B607 suppressed** in `main.py`: macOS system binary calls (`bioutil`, `defaults`) annotated with `# nosec B603 B607` — no user input is passed to either call.

### ✨ Features

- **`ModelManager` + `LLMClient`** (`model_manager.py`, `llm_client.py`): Centralised model routing with config-file-backed settings (`~/.config/openelia/config.json`). Supports local (Ollama), cloud (OpenAI / Anthropic / Google), and per-agent hybrid overrides. API keys stored exclusively via SecretStore, never in the config file. Resolution order: per-agent hybrid override → `brain_tier="expensive"` → global cloud mode → local Ollama default.
- **`/model` command** (`main.py`, `src/src/index.ts`, `src/src/cli.ts`): Interactive model configuration via `python main.py model status|set|auth|hybrid`. Full TypeScript CLI parity.
- **OpenClaw Section 8** added to `COMMANDS.txt`: Documents allowlist setup, `fetch_json`, `run_isolated`, `rotate_token`, `verify_chain`, all schemas, and SSRF protection details.

### 🐛 Bug Fixes

- **`base_agent.py` routing bypass**: `self.local_client` was instantiated directly via `AsyncOpenAI()`, bypassing `LLMClient` and `ModelManager`. Replaced with `LLMClient.create(brain_tier="local")` so all three local call-paths (`_compress_payload`, `_query_threat_intel`, reflective retry) route through the unified factory.
- **`orchestrator.py` routing bypass**: `Orchestrator.__init__` constructed `AsyncOpenAI()` directly from `ModelManager` config values instead of calling `LLMClient.create()`. Fixed to use `LLMClient.create(brain_tier="local")`.
- **`datetime.utcnow()` deprecation** (Python 3.12+): Fixed in `artifact_manager.py` (×2), `vector_manager.py`, and `mcp_servers/blue_telemetry/server.py`. All callsites now use `datetime.now(timezone.utc)`.
- **`middleware.py` inline regex flag**: `(?m)` mid-pattern caused `re.PatternError` on Python 3.14. Removed — `re.MULTILINE` was already passed to `re.compile()`.
- **`middleware.py` extra-field bypass**: `model_config = {"strict": True}` controls type coercion only. Added `"extra": "forbid"` to all five Pydantic schemas so unknown fields fail validation rather than being silently ignored.
- **`connector.py` double-`del` in `rotate_token`**: `del token_ref` in the `except` block caused `UnboundLocalError` when the `finally` block attempted a second deletion. Refactored to delete only in `finally`.

### 🧪 Tests

- **`tests/test_model_manager.py`**: 46 tests covering defaults, provider key storage, client config resolution, and `LLMClient` factory.
- **`tests/test_secret_store.py`**: Tests covering basic ops, in-memory cache, env fallback, keyring failure, and blob integrity.
- **`tests/test_openclaw.py`**: 50 tests covering all OpenClaw security boundaries — audit chain integrity, meta key blocking, URI scrubbing, schema validation, injection stripping, SSRF/allowlist enforcement, ephemeral token lifecycle, hermetic subprocess isolation, token rotation, and `fetch_json` happy/error paths.

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
