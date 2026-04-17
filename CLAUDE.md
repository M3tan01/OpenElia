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
