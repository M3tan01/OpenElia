import { useEffect, useState } from "react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { apiGet, CostResp } from "../api";
import { Panel } from "./Panel";

interface HeatTactic { coverage_pct: number; }
type Heatmap = Record<string, HeatTactic> | { error: string };

function heatColor(pct: number): string {
  if (pct >= 66) return "bg-emerald-600";
  if (pct >= 33) return "bg-amber-600";
  if (pct > 0) return "bg-redteam/70";
  return "bg-line";
}

export function CostMitre() {
  const [cost, setCost] = useState<CostResp | null>(null);
  const [heat, setHeat] = useState<Heatmap | null>(null);

  useEffect(() => {
    const load = () => {
      apiGet<CostResp>("/api/cost").then(setCost).catch(() => {});
      apiGet<Heatmap>("/api/heatmap").then(setHeat).catch(() => {});
    };
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  const series = (cost?.series ?? []).map((s) => ({ name: s.session.slice(-4), cost: Number(s.total_cost.toFixed(4)) }));
  const tactics = heat && !("error" in heat) ? Object.entries(heat) : [];

  return (
    <Panel
      title="Cost & MITRE Coverage"
      right={cost && <span className="text-[10px] text-slate-500">${cost.summary.total_historical_cost.toFixed(2)} / rem ${cost.summary.budget_remaining.toFixed(2)}</span>}
    >
      <div className="h-28 mb-3">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={series} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
            <CartesianGrid stroke="#16221f" />
            <XAxis dataKey="name" tick={{ fill: "#5d6b67", fontSize: 10 }} />
            <YAxis tick={{ fill: "#5d6b67", fontSize: 10 }} />
            <Tooltip contentStyle={{ background: "#07090a", border: "1px solid #16221f", fontSize: 12 }} />
            <Line type="monotone" dataKey="cost" stroke="#ffb000" dot={false} strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="font-display text-[10px] tracking-[0.18em] uppercase text-amber mb-1">ATT&CK coverage</div>
      {tactics.length === 0 && <div className="text-xs text-slate-600 italic">no heatmap (mitre_attack.json absent or no findings)</div>}
      <div className="grid grid-cols-2 gap-1">
        {tactics.map(([tactic, t]) => (
          <div key={tactic} className="flex items-center gap-2 text-[11px]">
            <span className={`inline-block w-3 h-3 rounded ${heatColor(t.coverage_pct)}`} />
            <span className="text-slate-400 truncate">{tactic}</span>
            <span className="text-slate-600 ml-auto">{Math.round(t.coverage_pct)}%</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}
