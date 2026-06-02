import { useEffect, useState } from "react";
import { apiGet, TaskResult } from "../api";
import { Panel } from "./Panel";

const TIERS: Record<string, string[]> = {
  RECON: ["pentester_recon", "defender_mon"],
  ANALYSIS: ["pentester_vuln", "defender_ana", "defender_hunt"],
  EXECUTION: ["pentester_exploit", "pentester_lat", "pentester_ex", "defender_res", "reporter_agent"],
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
  const [tasks, setTasks] = useState<TaskResult[]>([]);

  useEffect(() => {
    apiGet<TaskResult[]>("/api/tasks?limit=200").then(setTasks).catch(() => {});
  }, []);

  // Merge initial fetch with live stream, dedup by task_id (live wins).
  const merged = new Map<string, TaskResult>();
  [...tasks, ...liveTasks].forEach((t) => merged.set(t.task_id, t));
  const all = [...merged.values()];

  return (
    <Panel title="Agent Activity">
      {Object.keys(TIERS).map((tier) => {
        const rows = all.filter((t) => tierOf(t.agent_name) === tier);
        return (
          <div key={tier} className="mb-3">
            <div className="font-display text-[10px] tracking-[0.18em] uppercase text-amber mb-1">{tier} <span className="text-dim">({rows.length})</span></div>
            {rows.length === 0 && <div className="text-xs text-slate-600 italic">idle</div>}
            {rows.map((t) => (
              <div key={t.task_id} className="flex justify-between text-xs py-0.5">
                <span className="text-slate-300">{t.agent_name}</span>
                <span className={STATUS_COLOR[t.status] ?? "text-slate-400"}>{t.status}</span>
              </div>
            ))}
          </div>
        );
      })}
    </Panel>
  );
}
