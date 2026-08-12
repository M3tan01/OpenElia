import { apiGet, TaskResult } from "../api";
import { agentDisplayName } from "../agentNames";
import { Badge, Panel } from "./Panel";
import { usePoll } from "../usePoll";
import { useAgentsRoster } from "../useAgentsRoster";

// Canonical worker-pool order. Tier membership itself comes from /api/agents
// (backend AGENT_TIERS) — never re-encoded here.
const TIER_ORDER = ["RECON", "ANALYSIS", "EXECUTION", "OTHER"];

const STATUS_COLOR: Record<string, string> = {
  success: "text-emerald-400",
  error: "text-rose-400",
  skipped: "text-slate-500",
};

export function AgentActivity({ liveTasks }: { liveTasks: TaskResult[] }) {
  const { data: polledTasks, error } = usePoll<TaskResult[]>(
    () => apiGet<TaskResult[]>("/api/tasks?limit=200"),
    8000,
  );
  const { data: agentsData } = useAgentsRoster();

  // Build tier → agent-names map from the backend roster (single source of truth).
  const agents = agentsData?.agents ?? [];
  const tierAgents: Record<string, string[]> = {};
  const nameTier: Record<string, string> = {};
  for (const a of agents) {
    const tier = a.tier || "OTHER";
    (tierAgents[tier] ??= []).push(a.name);
    nameTier[a.name] = tier;
  }
  const tierOf = (agent: string): string => nameTier[agent] ?? "OTHER";

  // Show canonical tiers first, then any extra tiers the backend introduced.
  const tiers = [
    ...TIER_ORDER.filter((t) => tierAgents[t]?.length),
    ...Object.keys(tierAgents).filter((t) => !TIER_ORDER.includes(t)),
  ];

  // Merge polled tasks with live stream, dedup by task_id (live wins).
  const merged = new Map<string, TaskResult>();
  [...(polledTasks ?? []), ...liveTasks].forEach((t) => merged.set(t.task_id, t));
  const all = [...merged.values()];

  return (
    <Panel title="Agent Activity" right={error ? <Badge ok={false}>offline</Badge> : undefined}>
      {tiers.map((tier) => {
        const rows = all
          .filter((t) => tierOf(t.agent_name) === tier)
          .sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
        return (
          <div key={tier} className="mb-3">
            <div className="font-display text-[10px] tracking-[0.18em] uppercase text-amber mb-1">{tier} <span className="text-dim">({rows.length})</span></div>
            {rows.length === 0 &&
              (tierAgents[tier] ?? []).map((name) => (
                <div key={name} className="flex justify-between items-center text-xs py-0.5 opacity-50">
                  <span className="text-slate-400">{agentDisplayName(name)}</span>
                  <span className="text-slate-600 italic">ready</span>
                </div>
              ))}
            {rows.map((t) => (
              <div key={t.task_id} className="flex justify-between items-center text-xs py-0.5">
                <span className="text-slate-300">{agentDisplayName(t.agent_name)}</span>
                <span className="flex items-center gap-2">
                  {typeof t.priority === "number" && t.priority > 0 && (
                    <span className="font-mono text-[10px] text-amber/60" title="scheduling priority">
                      ▲{t.priority.toFixed(2)}
                    </span>
                  )}
                  <span className={STATUS_COLOR[t.status] ?? "text-slate-400"}>{t.status}</span>
                </span>
              </div>
            ))}
          </div>
        );
      })}
    </Panel>
  );
}
