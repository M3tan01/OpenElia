// Shared human-readable agent role titles. Keyed by the internal agent name
// (which is still what /api/run/* and task results use — only the displayed
// title changes). Falls back to a humanized form of the raw name so a new
// agent never renders as a bare snake_case id.

export const AGENT_DISPLAY_NAMES: Record<string, string> = {
  pentester_recon:   "Reconnaissance Operator",
  pentester_vuln:    "Vulnerability Analyst",
  pentester_exploit: "Exploitation Operator",
  pentester_persist: "Persistence Operator",
  pentester_lat:     "Lateral Movement Operator",
  pentester_ex:      "Exfiltration Operator",
  defender_mon:      "Monitoring Analyst",
  defender_ana:      "Triage Analyst",
  defender_hunt:     "Threat Hunter",
  defender_res:      "Incident Responder",
  reporter_agent:    "Reporter",
};

export function agentDisplayName(name: string): string {
  if (AGENT_DISPLAY_NAMES[name]) return AGENT_DISPLAY_NAMES[name];
  return name
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
