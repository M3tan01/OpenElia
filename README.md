<img width="1201" height="687" alt="image" src="https://github.com/user-attachments/assets/f238c5e5-3843-4b7a-994d-1a58dfe29b21" />


# 🛡️ OpenElia Core

**AI-assisted purple-team orchestration platform**

OpenElia is a multi-agent cybersecurity operations library for offensive (red), defensive (blue), and collaborative (purple) operations. It uses LLMs and the Model Context Protocol (MCP) to drive agents through scanning, triage, and remediation workflows under an enforced Rules-of-Engagement scope. It is a research/lab tool — most integrations require configuration (API keys, Docker, Ollama) to be useful; see **Maturity & requirements** below.

## **Important Note:**
**Check COMMANDS.txt for COMPLETE COMMAND REFERENCE & MODEL CONFIGURATION GUIDE!**

## 🧭 Maturity & requirements

OpenElia is a lab/research tool, not a turnkey product. Honest status of the moving parts:

- **Works out of the box:** the CLI (`check`, `status`, `red`/`blue`/`purple`/`forge`, `nmap`/`msf`, `sbom`, `archive`, `lock`/`unlock`), the orchestrator/agent engine, the TUI and web dashboard, and the RoE scope gate.
- **Needs configuration to be useful:** an LLM provider (local Ollama **or** a cloud key), Docker for sterile offensive execution, and the optional threat-intel keys in the tables below. Each integration **degrades gracefully** when its key is absent (the feature is skipped, not broken).
- **Roadmap, not built:** multi-operator team server (mTLS, concurrent operators). See `docs/superpowers/plans/2026-06-03-v2-multi-operator.md`. The current console is single-operator, localhost-only.

## 🚀 5-Tier Security Architecture

1.  **Identity & Configuration**: API keys stored in OS-native keystores (macOS Keychain, Linux Secret Service). Credentials at rest are **Fernet AES-256 encrypted** (`state/vault.bin`). The encryption key never touches disk — stored exclusively in the OS keyring.
2.  **Double Firewall**: Every tool call is validated by a **Mathematical Firewall** (scope/IP validation, fail-closed without `roe.json`) and a **Semantic Firewall** (payload sanitization). SIEM webhooks use a strict **hostname allowlist** (`SIEM_WEBHOOK_ALLOWLIST`), not a blocklist.
3.  **Sterile Execution**: Offensive modules run inside **ephemeral, rootless Docker containers** with `cap_drop=ALL`. MSF commands are written to a signed temp resource file — never injected as CLI strings. Nmap targets and args are validated via `ipaddress` and metacharacter stripping before execution.
4.  **Immutable Auditing**: Every audit event carries an **HMAC-SHA256 chain link** over the previous entry. Tampering with any entry breaks the chain. All sensitive files are written with `chmod 0o600`.
5.  **Supply Chain Integrity**: Hash-locked dependencies, automated SAST/Secret scanning, and a Software Bill of Materials (`python main.py sbom`).

## 🛠️ Key Features

*   🔴 **Red Team (Pentester)**: LLM-driven reconnaissance, vulnerability assessment, and exploitation using the **Atomic Red Team** library, gated by human-in-the-loop confirmation on sensitive actions.
*   🔵 **Blue Team (Defender)**: Log analysis, SIEM-style telemetry, and remediation (block IP via iptables, kill process via SIGKILL). Operates in simulation mode by default; live execution requires `BLUE_REMEDIATE_LIVE=1` plus an RBAC token.
*   🟣 **Purple Team**: N-iteration attack/defend loops with coverage delta tracking, early exit, and adaptive red task seeding based on previous blue alert types.
*   📺 **Dashboard**: Real-time TUI with MITRE heatmap, findings, red/blue logs, and pivot session panel — or a local browser console (`dashboard --web`, 127.0.0.1 only) with the same telemetry plus interactive control (run red/blue/purple, kill-switch, model selection). See `webdash/README.md`.
*   🧠 **Retry with self-correction**: On a tool error, an agent reflects on the cause and reissues a corrected command (max 3 retries).
*   🕵️ **Stealth Mode (OPSEC)**: Randomized timing jitter and living-off-the-land command preferences to reduce noise.
*   🐝 **Parallel host scanning**: A CIDR target fans out into concurrent per-host scanning threads.
*   ⚖️ **Risk/Success heuristics**: Estimates of exploit success and detection risk to inform loud-action decisions.
*   🚨 **Shadow Shell**: Interactive human-AI handoff for live session control.
*   🔐 **Access control**: OS-keyring-backed secrets and a token-gated RBAC check for live remediation.
*   🛑 **Global Kill-Switch**: Operator fail-safe to pause or terminate active agents (`lock`/`unlock`).
*   📡 **Message bus**: Inter-agent messaging for coordination.
*   ⚡ **Efficiency**: Semantic caching (ChromaDB) and large-output auto-compression to reduce API cost and latency.

## 📁 Project Structure

```
OpenElia/
├── main.py                 # Main entry point for Python engine
├── orchestrator.py         # Core orchestration logic
├── agents/                   # AI agent implementations
│   ├── base_agent.py         # Base agent class
│   ├── reporter_agent.py     # Executive reporting, MITRE heatmap, chain of custody
│   ├── blue/                 # Defensive agents
│   │   ├── defender_ana.py   # Tier 2 LLM-based triage
│   │   ├── defender_hunt.py  # Proactive threat hunting
│   │   ├── defender_mon.py   # Tier 1 Sigma/regex monitoring
│   │   ├── defender_os.py    # Blue team orchestrator
│   │   └── defender_res.py   # Tier 4 containment & response
│   └── red/                  # Offensive agents
│       ├── pentester_os.py   # Red team phase orchestrator
│       ├── pentester_recon.py# Reconnaissance phase
│       ├── pentester_vuln.py # Vulnerability assessment
│       ├── pentester_exploit.py # Exploitation phase
│       ├── pentester_lat.py  # Lateral movement phase
│       └── pentester_ex.py   # Exfiltration phase
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
├── webdash/                # FastAPI + React browser console (127.0.0.1 only)
├── state/                  # Persistent state and databases
├── requirements.txt        # Python dependencies
├── pyproject.toml          # Python project config
├── roe.json                # Rules of Engagement
├── setup.sh & setup.ps1    # Installation scripts
└── scrub.py                # Data sanitization tool
```

## 🏁 Getting Started

### Prerequisites
- Python 3.11+ (required)
- Docker (optional — for sterile execution of offensive tooling)
- Ollama (optional — local LLM, e.g. `llama3.1:8b`; cloud providers work as an alternative)
- Node.js 18+ (optional — only to rebuild the web dashboard frontend)

### Installation

**Python Engine (Required):**
```bash
# Clone the Repository
git clone https://github.com/M3tan01/OpenElia.git
cd OpenElia

# Create and activate a virtual environment (required on Debian/Ubuntu)
python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# Install Python dependencies
pip install -r requirements.txt

# Or install as editable package
pip install -e .

# Or use setup scripts (also handles venv creation)
chmod +x setup.sh && ./setup.sh  # Unix/macOS
# .\setup.ps1  # Windows

# Verify environment readiness
python3 main.py check
```

> **Note (Debian/Ubuntu):** If `python3 -m venv` fails with an `ensurepip` error, install the venv package first:
> ```bash
> sudo apt install python3.12-venv
> ```
> Then re-run the venv creation steps above.

> **Note:** Always activate the virtual environment before running any `python3 main.py` or `pip install` commands:
> ```bash
> source .venv/bin/activate
> ```

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
python3 scrub.py

# Package the entire engagement into a secure, hashed Case File
python3 main.py archive
# Note: On first run, a GUI prompt will ask you to set a password for the
# OS keyring ("Choose password for new keyring"). Enter and confirm a password,
# then click Continue. This keyring protects your API keys and vault encryption key.
# Leave the password blank only if you are in a headless/server environment.

# Generate Software Bill of Materials
python3 main.py sbom
```

### Usage

> **Before running any command**, activate the virtual environment:
> ```bash
> source .venv/bin/activate
> ```

#### Python CLI (Direct)
```bash
# Verify environment readiness
python3 main.py check

# Launch the interactive War Room TUI
python3 main.py dashboard

# Launch the browser C2 console (FastAPI + React, 127.0.0.1 only)
# Prints http://127.0.0.1:8765/#token=<token> — open the FULL url incl. the #token fragment.
# First time only (static/ is gitignored — no UI until built):
#   cd webdash/frontend && npm install && npm run build
python3 main.py dashboard --web            # --port 8888 to change port

# Run a red team engagement (Single Target)
python3 main.py red --target 10.10.10.50 --stealth

# Run a parallel subnet swarm (CIDR Range) emulating APT29
python3 main.py red --target 10.10.10.0/29 --apt apt29

# Run a collaborative purple team loop (2 iterations)
python3 main.py purple --target 10.10.10.50 --iterations 2

# Forge a topology/RoE-constrained adversary profile from a MITRE actor, then run it
python3 main.py forge --actor APT29 --auto-commit
python3 main.py red --target 10.10.10.50 --apt tailored_apt29

# Generate executive report with MITRE heatmap and chain of custody
python3 main.py report
python3 main.py report --brain-tier expensive

# Execute an approved response action by its logged ID
python3 main.py execute-remediation --action-id 42
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
| `OPENELIA_ROE_PATH` | Override path to the RoE file for the scope gate | Falls back to `roe.json` (cwd) |
| `SIEM_WEBHOOK_ALLOWLIST` | Comma-separated approved SIEM hostnames | All webhook forwarding blocked |
| `THEHIVE_URL` | TheHive instance base URL | TheHive case dispatch falls back to local SQLite only |
| `THEHIVE_API_KEY` | TheHive API key | TheHive case dispatch falls back to local SQLite only |
| OS Keyring secrets | API keys, vault encryption key | Prompted interactively on first run |
| `BLUE_REMEDIATE_LIVE` | Set to `1` to enable live iptables/kill execution | Runs in safe simulation mode |
| `BLUE_REMEDIATE_RBAC_TOKEN` | RBAC token env var (must match keyring value) | Live remediation actions denied |

**Optional threat-intel / cloud-LLM keys** (OS keyring or env; all degrade gracefully):

| Variable | Purpose | Effect if missing |
|----------|---------|------------------|
| `GOOGLE_API_KEY` | Google/Gemini cloud LLM provider (`GEMINI_API_KEY` accepted as a legacy alias) | Google cloud provider unavailable |
| `SHODAN_API_KEY` | Shodan passive host intel **and** exploit search (commercial; limited free tier) | Those lookups skipped |
| `VT_API_KEY` | VirusTotal hash/IP/domain lookups (commercial; rate-limited free public API) | VirusTotal lookups skipped |
| `ABUSEIPDB_API_KEY` | AbuseIPDB IP reputation (free tier) | AbuseIPDB lookups skipped |

> **No commercial key required.** IOC enrichment works on the free-tier path alone
> (AbuseIPDB). Shodan and VirusTotal are optional commercial enhancers —
> every lookup degrades gracefully when its key is absent.

> The scope gate hot-reloads `roe.json` (or `OPENELIA_ROE_PATH`) on file change, so a scope-**narrowing** edit takes effect mid-session without a restart. A removed RoE file fails closed.

### SIEM Webhook Allowlist

Set before running the SIEM MCP server:

```bash
export SIEM_WEBHOOK_ALLOWLIST="splunk.corp.com,siem.internal"
```

### Vault Encryption

Credentials stored via `store_credential` are **automatically encrypted** with Fernet AES-256. The key is generated on first use and stored in the OS keyring under `VAULT_ENCRYPTION_KEY`. If a legacy plaintext `state/vault.json` exists, it is migrated and deleted on first load.

---
*Disclaimer: This tool is for authorized security testing and research purposes only.*
