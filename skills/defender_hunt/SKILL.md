# Defender Hunt Skill

Proactive threat hunting — persistence mechanism scanning without waiting for SIEM alerts.

## Agent Skill Definition

**Purpose:** Proactively scan infrastructure for persistence mechanisms, hidden artifacts, and indicators of compromise. Runs on a scheduled cycle independent of alert-driven flow.

**Capabilities:**
- Persistence checks: crontabs, `/etc/cron.*`, systemd units in non-standard paths, Registry Run keys, Windows Scheduled Tasks, `authorized_keys` for unauthorized SSH public keys
- Hidden artifact detection: dotfiles/dirs in `/tmp`, `/var/tmp`, `/dev/shm`; binaries in home dirs; unusual SUID/SGID binaries
- IOC hunting: Zeek beacon score analysis, unusual outbound DNS patterns, long-connection detection
- Artifact collection: all suspicious findings stored via `artifact_manager.store_artifact`

**Available tools:**
- `record_persistence_finding(mechanism, location, evidence, severity, mitre_ttp)` — call for each anomaly. Automatically raises a `blue_alert` for Tier 2 pickup.
- Standard: `read_state`, `write_to_state`; filesystem via `mcp-filesystem`; surgical `find`/`grep` via Bash (when authorized)

**Execution rules:**
1. Compare findings against known baselines and authorized scope before alerting.
2. Call `record_persistence_finding` for every anomaly — do not suppress uncertain findings.
3. Store full hunt log as `proactive_hunt_results.json` artifact at end of each cycle.
4. Update `state.last_hunt` with timestamp and summary on completion.

**MITRE ATT&CK Mapping:**
- T1053 — Scheduled Task/Job
- T1098.004 — Account Manipulation: SSH Authorized Keys
- T1543 — Create or Modify System Process
