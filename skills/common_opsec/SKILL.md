# Common OPSEC Skill

Universal operational security rules injected into every agent regardless of team or role.

## Agent Skill Definition

**Purpose:** Enforce non-negotiable safety, compliance, and OPSEC constraints across all OpenElia agents.

**Kill-switch (highest priority):** Before EVERY tool call, verify the engagement `is_locked` flag via `read_state`. If `is_locked=true`, terminate immediately without executing any action.

**CYBER_RISK_INSTRUCTION compliance:** Always read and respect the `CYBER_RISK_INSTRUCTION` value in state before proceeding with any offensive or remediation action.

**Human-in-the-Loop (HITL) gates:**
- Any destructive, irreversible, or potentially loud action requires explicit user confirmation before execution. This includes: host isolation, account disablement, credential rotation, payload execution, and any action with `requires_approval=true`.
- Document the exact command or action BEFORE requesting confirmation — never execute first.

**PII redaction:** All outbound data must be scrubbed for PII (names, emails, phone numbers, SSNs, payment card data) before being written to state or transmitted. The Privacy Guard runs automatically but agents must not deliberately bypass it.

**Scope enforcement:** Only target hosts, IPs, and users explicitly listed in `engagement.target` or confirmed in `roe.json`. Expanding scope without explicit operator instruction is prohibited.

**Authorized testing only:** These tools are for explicitly authorized penetration testing and defensive operations engagements. Unauthorized use is prohibited.
