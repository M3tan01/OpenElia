import { AgentsResp, apiGet } from "./api";
import { usePoll } from "./usePoll";

// Module-level — survives unmount, shared by every caller in this tab.
let cachedAgents: AgentsResp | null = null;

/**
 * Shared /api/agents poll. AgentActivity and AgentsView are mutually exclusive
 * views (only one mounts at a time, see App.tsx's activeView switch), so this
 * isn't deduping concurrent requests — it seeds a fresh mount with the last
 * fetched roster so switching views doesn't show a loading flash while the
 * 30s poll re-fetches in the background.
 */
export function useAgentsRoster() {
  const result = usePoll<AgentsResp>(() => apiGet<AgentsResp>("/api/agents"), 30000);
  if (result.data) cachedAgents = result.data;
  return { ...result, data: result.data ?? cachedAgents };
}
