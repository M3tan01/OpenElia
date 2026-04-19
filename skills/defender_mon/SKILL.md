# Defender Monitoring Skill

Tier 1 — zero-LLM, continuous log ingestion with regex/threshold-based alert generation.

## Agent Skill Definition

**Purpose:** Continuously analyse log streams using Sigma-style rules; emit high-confidence alerts for Tier 2 escalation. No LLM calls — pure regex matching with sliding-window counters.

**Capabilities:**
- SIGMA rule matching: AND-pattern logic with sliding-window threshold counting
- Covered TTPs: T1110.003 (password spray), T1490 (VSS deletion), T1071.001 (C2 beacon), T1059.001 (Office→shell), T1003.001 (LSASS/Mimikatz), T1547.001 (Registry Run), T1021.001 (lateral RDP), T1566.002 (phishing click)
- Sliding time window: configurable per rule (default 1 hour); threshold events must occur within the window to fire
- Alert emission: `add_blue_alert(alert_type, description, severity, source)` written to state for Tier 2 pickup

**Execution rules:**
1. Call `analyze(log_text)` per log batch — returns list of fired alert dicts.
2. Only high-confidence alerts (all AND-patterns matched, threshold met) are returned.
3. Call `reset_counters()` at the start of each new engagement.

**Output format:** List of alert dicts: `{type, description, severity, mitre, source}`. Written to `state.blue_alerts` for defender_ana pickup.
