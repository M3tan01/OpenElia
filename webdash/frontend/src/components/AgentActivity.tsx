import { apiGet, TaskResult } from "../api";
import { agentDisplayName } from "../agentNames";
import { Badge, Panel } from "./Panel";
import { usePoll } from "../usePoll";

const TIERS: Record<string, string[]> = {
  RECON: ["pentester_recon", "defender_mon"],
  ANALYSIS: ["pentester_vuln", "defender_ana", "defender_hunt"],
  EXECUTION: ["pentester_exploit", "pentester_persist", "pentester_lat", "pentester_ex", "defender_res", "reporter_agent"],
};

function tierOf(agent: string): string {
  for (const [tier, agents] of Object.entries(TIERS)) if (agents.includes(agent)) return tier;
  return "OTHER";
}

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

  // Merge polled tasks with live stream, dedup by task_id (live wins).
  const merged = new Map<string, TaskResult>();
  [...(polledTasks ?? []), ...liveTasks].forEach((t) => merged.set(t.task_id, t));
  const all = [...merged.values()];

  return (
    <Panel title="Agent Activity" right={error ? <Badge ok={false}>offline</Badge> : undefined}>
      {Object.keys(TIERS).map((tier) => {
        const rows = all
          .filter((t) => tierOf(t.agent_name) === tier)
          .sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
        return (
          <div key={tier} className="mb-3">
            <div className="font-display text-[10px] tracking-[0.18em] uppercase text-amber mb-1">{tier} <span className="text-dim">({rows.length})</span></div>
            {rows.length === 0 && <div className="text-xs text-slate-600 italic">idle</div>}
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
