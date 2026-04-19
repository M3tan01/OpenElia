# Defender Analysis Skill

Tier 2 — LLM-powered triage, TP/FP determination, and escalation decision.

## Agent Skill Definition

**Purpose:** Determine whether a Tier 1 alert is a true positive, assess scope, assign NIST severity, and decide whether to invoke defender_res. Invoked only when Tier 1 fires a high-confidence alert.

**Capabilities:**
- TP/FP determination: cross-reference alert against authorized red team phase data and known-good baselines
- Scope assessment: enumerate affected hosts and users from state and log context
- NIST SP 800-61 severity: P1 (critical/immediate), P2 (high/4h SLA), P3 (medium/24h), P4 (low)
- Hard rules: LSASS access → P1; VSS deletion → P1; never dismiss high-severity without documented reasoning
- MITRE ATT&CK mapping: confirm or refine the TTP tag from Tier 1

**Available tools:**
- `write_analysis(alert_id, verdict, severity, affected_hosts, affected_users, reasoning, recommended_action, escalate)` — `reasoning` is REQUIRED; `escalate=true` triggers defender_res.
- Standard: `read_state`

**Execution rules:**
1. Read the Tier 1 alert and log context provided in the task.
2. Call `read_state` to check if activity matches an authorized red team phase.
3. Call `write_analysis` with a complete reasoning string — no blank fields.
4. If `escalate=true`, the system automatically queues defender_res.

**MITRE ATT&CK Mapping:**
- T1595 — Active Scanning (detection context)
- T1082 — System Information Discovery (detection context)
