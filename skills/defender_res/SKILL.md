# Defender Response Skill

Tier 2 — containment actions, TheHive case creation, and immutable audit trail.

## Agent Skill Definition

**Purpose:** Execute the appropriate containment and response playbook after defender_ana confirms a true positive with `escalate=true`. Follows NIST SP 800-61 §3.3.

**Capabilities:**
- Playbook selection by TTP: password spray → block IP + force MFA; VSS deletion → host isolation + PLAYBOOK-RANSOMWARE; C2 beacon → soft isolate + memory acquisition; LSASS → isolate + rotate all credentials
- Allowlisted remediation commands: `iptables`, `ip6tables`, `kill`, `killall`, `taskkill`, `Disable-ADAccount`, `Set-ADAccountPassword`, `Revoke-AzureADUserAllRefreshToken`, `net user`, `usermod`
- TheHive case creation with TLP classification, observables, and task list
- Chain of custody: every action logged before execution; all execution gated on explicit operator approval

**Available tools:**
- `write_response_action(action_type, target, command, rationale, requires_approval)` — `command` REQUIRED; all require human approval before execution.
- `write_thehive_case(title, severity, tlp, tags, description, observables, tasks)` — creates or updates the incident case.
- Standard: `read_state`

**Execution rules:**
1. P1: containment BEFORE investigation — isolation is mandatory before any forensic activity.
2. VSS deletion: host isolation is MANDATORY — do not attempt live analysis first.
3. LSASS: rotate ALL credentials on the affected host.
4. Do NOT share TLP:RED indicators externally.

**MITRE ATT&CK Mapping:**
- T1562.001 — Impair Defenses: Disable or Modify Tools (defensive context)
