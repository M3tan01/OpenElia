# OpenElia Instructions

This project is a multi-agent cybersecurity operations library. It integrates a Python-based agent engine with a Claude Code-style TypeScript CLI.

## Core Agents
- **Pentester (Red Team)**: Use for offensive operations, recon, and exploitation. **Mandate**: Prioritize Atomic Red Team techniques and use the **Shadow Shell** tool for human handoffs.
- **Defender (Blue Team)**: Use for defensive operations, log analysis, and active remediation. **Mandate**: Perform proactive threat hunting for persistence.
- **Reporter**: Use for generating executive summaries, tactical MITRE heatmaps, and technical reports. **Mandate**: Include a professional **Forensic Chain of Custody** log for all recovered artifacts.
- Use `/agent Pentester`, `/agent Defender`, or `/agent Reporter` to switch contexts.

## Specialized Tools
- **openelia**: The primary tool for executing cybersecurity tasks.
  - `command`: 'red', 'blue', 'purple', 'status', 'dashboard', 'check', 'nmap', 'msf', 'sbom', 'archive', 'lock', 'unlock'
  - `target`: IP or CIDR Range (e.g. 10.0.0.0/24).
  - `stealth`: Boolean flag for OPSEC (jitter, slow timing, LotL).
  - `cred_alias`: Reference to a credential in the secure vault.
  - `brain_tier`: 'local' (Ollama) or 'expensive' (Claude/GPT).
  - `proxy_port`: SOCKS5 port for lateral movement.
  - `shadow_shell`: (Internal Tool) Used for interactive human-AI handoffs.

## Operational Standards
- Always respect the `CYBER_RISK_INSTRUCTION`.
- Only perform authorized security testing.
- **Rules of Engagement (RoE)**: Strictly adhere to the constraints defined in `roe.json`. 
- **Risk Intelligence**: Analyze the **Success Probability** and **Detection Risk** provided by the Orchestrator before proceeding with loud actions.
- **Human-in-the-Loop (HITL)**: You MUST obtain explicit user confirmation before executing any sensitive offensive tool.
- **Data Privacy**: Outbound traffic is automatically redacted for PII by the **Privacy Guard**.
- **Self-Healing**: If a tool call fails, analyze the error and issue a corrected command (Autonomic Resilience).
- **Efficiency**: Use the 'mcp-memory' search to avoid redundant tool calls. Massive outputs are automatically compressed by the framework to preserve your context.
- **Subnet Swarming**: When a CIDR target is provided, coordinate parallel offensive threads for each host.
- **Kill-Switch**: Check the `is_locked` flag before every tool execution. If set, terminate immediately.
- **Coordination**: Use the `send_message` tool to broadcast intent and coordinate strategy with other agents.

## Architecture
- **Engine**: Python (`main.py`, `agents/`, `orchestrator.py`)
- **Platform**: TypeScript (`src/`)
- **Persistence**: SQLite Relational Backend (`state/engagement.db`).
- **Intelligence Layer**:
  - `mcp-graph`: Attack Surface Knowledge Graph (`NetworkX`).
  - `mcp-memory`: Long-term vectorized engagement memory (`ChromaDB`).
  - `mcp-atomic`: Local library of research-backed **Atomic Red Team** tests.
- **Sterile Execution**: Offensive modules run in rootless, ephemeral Docker containers.
- **Immutable Auditing**: Fail-closed JSON audit log in `state/audit.log`.

## Architectural Directive: Highly Concurrent, Stateless Micro-Agent Framework

### Core Rules (enforce in every session)

**Token Economy & Context Isolation** — No single LLM prompt may contain global state or the full tool registry. Violating this is a hard error.

**Stateless Orchestrator**
- `orchestrator.py` is a message broker only — it classifies, enqueues, and returns. It never holds agent state or performs reasoning beyond task classification.
- After routing, the Orchestrator's LLM context is discarded. State crosses boundaries via typed `AgentTask` / `AgentResult` JSON payloads only.
- A fresh `AsyncWorkerPool` is created per `route()` call — pools are single-use.

**Just-In-Time (JIT) Resource Injection**
- Never load all plugins/skills globally. Use `JITLoader` to inject only the 2–3 skills required for the specific agent being spun up.
- `pre_run_hook` injects JIT context. `post_run_hook` extracts output and calls `context.clear()`. `error_hook` writes to `state/audit.log`.

**Tier-Based Async Worker Pool**
- Three tiers: `RECON` (data gathering) → `ANALYSIS` (reasoning) → `EXECUTION` (action).
- Each tier has its own `asyncio.Queue` and N concurrent workers (`core/worker_pool.py`).
- Agents are lazily imported and instantiated inside `_run_agent()` — never at import time.

**MCP/LSP Gateway Gate**
- All MCP and LSP queries must go through `MCPGateway`. Never call MCP servers directly from agent code.
- `EXECUTION` tier agents are blocked from querying servers — they receive pre-summarized context from `ANALYSIS` tier only.
- Responses exceeding `max_tokens` words are summarized by the local LLM before being returned.

**Key files**
- `core/schemas.py` — single source of truth for `AgentTask`, `AgentResult`, `AgentTier`, `Domain`
- `core/worker_pool.py` — `AsyncWorkerPool`, `MAX_RETRIES = 3`
- `core/hooks.py` — `pre_run_hook`, `post_run_hook`, `error_hook`
- `core/mcp_gateway.py` — `MCPGateway`, `GatewayAccessError`
- `core/lsp_server.py` — pygls 2.x LSP server (`pygls.lsp.server.LanguageServer`)
- `jit_loader.py` — `JITLoader`, `get_skills_for_agent()`
