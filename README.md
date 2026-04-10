# 🛡️ OpenElia Core

**Autonomous AI-Powered Purple Team Orchestration Platform**

OpenElia is a next-generation cybersecurity operations library designed to handle multi-agent offensive and defensive operations. Powered by LLMs and the Model Context Protocol (MCP), it provides a secure, high-performance ecosystem for simulating realistic attacks and automating real-time defense.

## **Important Note:**
**Check COMMANDS.txt for COMPLETE COMMAND REFERENCE & MODEL CONFIGURATION GUIDE!**

## 🚀 5-Tier Security Architecture

1.  **Identity & Configuration**: API keys stored in OS-native keystores (macOS Keychain, Linux Secret Service). Credentials at rest are **Fernet AES-256 encrypted** (`state/vault.bin`). The encryption key never touches disk — stored exclusively in the OS keyring.
2.  **Double Firewall**: Every tool call is validated by a **Mathematical Firewall** (scope/IP validation, fail-closed without `roe.json`) and a **Semantic Firewall** (payload sanitization). SIEM webhooks use a strict **hostname allowlist** (`SIEM_WEBHOOK_ALLOWLIST`), not a blocklist.
3.  **Sterile Execution**: Offensive modules run inside **ephemeral, rootless Docker containers** with `cap_drop=ALL`. MSF commands are written to a signed temp resource file — never injected as CLI strings. Nmap targets and args are validated via `ipaddress` and metacharacter stripping before execution.
4.  **Immutable Auditing**: Every audit event carries an **HMAC-SHA256 chain link** over the previous entry. Tampering with any entry breaks the chain. All sensitive files are written with `chmod 0o600`.
5.  **Supply Chain Integrity**: Hash-locked dependencies, automated SAST/Secret scanning, and a Software Bill of Materials (`python main.py sbom`).

## 🛠️ Key Features

*   🔴 **Red Team (Pentester)**: Autonomous reconnaissance, vulnerability assessment, and exploitation using the **Atomic Red Team** library.
*   🔵 **Blue Team (Defender)**: Real-time log analysis, SIEM-style telemetry, and active remediation (block IP, kill process).
*   🟣 **Purple Team (Simulation)**: Collaborative, iterative attack/defend loops (**Continuous Chaos**) for rapid security drills.
*   📺 **War Room Dashboard**: Live, real-time TUI for situational awareness over the digital battlefield.
*   🧠 **Autonomic Self-Healing**: Agents automatically detect tool errors, reflect on the cause, and issue corrected commands.
*   🕵️ **Stealth Mode (OPSEC)**: Randomized jitter and LotL techniques to evade detection.
*   🐝 **Subnet Swarming**: Launch parallel agent threads to scan and assess entire CIDR ranges simultaneously.
*   ⚖️ **Risk/Success Engine**: Real-time probabilistic modeling of exploit success and detection risk.
*   🚨 **Shadow Shell**: Interactive human-AI tactical handoff for live session control.
*   🔐 **Role-Based Access Control (RBAC)**: Hardware-backed identity verification and OS-level privilege enforcement.
*   🛑 **Global Kill-Switch**: A technical fail-safe that allow the operator to instantly pause or terminate all active agents.
*   📡 **Strategic Message Bus**: Enables real-time inter-agent communication and coordination.
*   ⚡ **Elite Efficiency**: Built-in **Semantic Caching** (ChromaDB) and **Massive Output Auto-Compression** to slash API costs and latency.

## 📁 Project Structure

```
OpenElia/
├── main.py                 # Main entry point for Python engine
├── orchestrator.py         # Core orchestration logic
├── agents/                 # AI agent implementations
│   ├── base_agent.py       # Base agent class
│   ├── blue/               # Defensive agents
│   │   ├── defender_ana.py # Anomaly detection
│   │   ├── defender_hunt.py# Threat hunting
│   │   ├── defender_mon.py # Monitoring
│   │   ├── defender_os.py  # OSINT
│   │   └── defender_res.py # Response
│   └── red/                # Offensive agents
│       ├── pentester_ex.py # Exploitation
│       ├── pentester_exploit.py
│       ├── pentester_lat.py# Lateral movement
│       ├── pentester_os.py # OSINT
│       └── pentester_recon.py
├── adversaries/            # Adversary emulation profiles
│   ├── apt29.json          # APT29 TTPs
│   └── fin7.json           # FIN7 TTPs
├── artifacts/              # Generated artifacts and evidence
├── lab/                    # Testing environment
│   └── docker-compose.yml  # Lab setup
├── mcp_servers/            # Model Context Protocol servers
│   ├── atomic/             # Atomic Red Team integration
│   ├── blue_remediate/     # Automated remediation
│   ├── blue_telemetry/     # Telemetry collection
│   ├── graph/              # Attack surface graph
│   ├── memory/             # Long-term memory
│   ├── pivot/              # Pivoting tools
│   ├── red_recon/          # Reconnaissance
│   ├── siem/               # SIEM integration
│   ├── threat_intel/       # Threat intelligence
│   └── vault/              # Secure credential storage
├── skills/                 # Domain-specific skill modules
├── src/                    # TypeScript CLI
│   ├── cli.ts              # CLI implementation
│   ├── index.ts            # Entry point
│   ├── package.json        # Node.js dependencies
│   └── tsconfig.json       # TypeScript config
├── state/                  # Persistent state and databases
├── requirements.txt        # Python dependencies
├── pyproject.toml          # Python project config
├── roe.json                # Rules of Engagement
├── setup.sh & setup.ps1    # Installation scripts
└── scrub.py                # Data sanitization tool
```

## 🏁 Getting Started

### Prerequisites
- Docker (for sterile execution)
- Ollama (running locally with `llama3.1:8b` or similar)
- Python 3.11+
- Node.js 18+ (for TypeScript CLI)

### Installation

**Python Engine (Required):**
```bash
# Clone the Repository
git clone https://github.com/M3tan01/OpenElia.git

# Install Python dependencies
pip install -e .

# Or use setup scripts
chmod +x setup.sh && ./setup.sh  # Unix/macOS
# .\setup.ps1  # Windows
```

**TypeScript CLI (Optional but Recommended):**
```bash
# Install TypeScript CLI
cd src
npm install
npm run build
npm link  # Make globally available as 'openelia-cli'
```

**Global Command (Optional):**
```bash
pip install .
# Now you can use 'openelia' instead of 'python main.py'
```

### Proving Ground (Optional)
Spin up a standardized, vulnerable lab environment for immediate testing:
```bash
cd lab
docker-compose up -d
```

### Sanitization & Compliance
Ensure your data is purged before pushing, or generate forensic artifacts:
```bash
# Purge all local state and artifacts
python scrub.py

# Package the entire engagement into a secure, hashed Case File
python main.py archive

# Generate Software Bill of Materials
python main.py sbom
```

### Usage

#### Python CLI (Direct)
```bash
# Verify environment readiness
python main.py check

# Launch the interactive War Room TUI
python main.py dashboard

# Run a red team engagement (Single Target)
python main.py red --target 10.10.10.50 --stealth

# Run a parallel subnet swarm (CIDR Range) emulating APT29
python main.py red --target 10.10.10.0/29 --apt apt29

# Run a collaborative purple team loop (2 iterations)
python main.py purple --target 10.10.10.50 --iterations 2
```

#### TypeScript CLI (Enhanced UX)
```bash
# Interactive mode (recommended)
openelia-cli

# Direct commands
openelia-cli red --target 10.10.10.50 --stealth
openelia-cli check
openelia-cli status
openelia-cli dashboard

# Switch agents in interactive mode
openelia-cli interactive
> agent Pentester
> red --target 10.10.10.50
```

#### Agent Commands
```bash
# Switch to Pentester agent
/agent Pentester

# Generate a final report with MITRE ATT&CK coverage
/agent Reporter
```

## 📜 Rules of Engagement

All operations are governed by `roe.json`. The scope validator **fails closed** — if `roe.json` is missing or `authorized_subnets` is empty, every target is blocked.

```json
{
  "authorized_subnets": ["10.10.10.0/24"],
  "blacklisted_ips": ["10.10.10.1", "10.10.10.254"]
}
```

> **Remove `127.0.0.0/8` from `authorized_subnets` before any real engagement.** It is included in the default config for local lab use only.

Outbound traffic is automatically redacted for PII by the **Privacy Guard**. All tool results are sanitized for prompt injection before re-entering the model context.

## ⚙️ Required Configuration

| Variable / File | Purpose | Effect if missing |
|----------------|---------|------------------|
| `roe.json` with `authorized_subnets` | Defines legal target scope | All operations blocked |
| `SIEM_WEBHOOK_ALLOWLIST` | Comma-separated approved SIEM hostnames | All webhook forwarding blocked |
| OS Keyring secrets | API keys, vault encryption key | Prompted interactively on first run |

### SIEM Webhook Allowlist

Set before running the SIEM MCP server:

```bash
export SIEM_WEBHOOK_ALLOWLIST="splunk.corp.com,siem.internal"
```

### Vault Encryption

Credentials stored via `store_credential` are **automatically encrypted** with Fernet AES-256. The key is generated on first use and stored in the OS keyring under `VAULT_ENCRYPTION_KEY`. If a legacy plaintext `state/vault.json` exists, it is migrated and deleted on first load.

---
*Disclaimer: This tool is for authorized security testing and research purposes only.*
