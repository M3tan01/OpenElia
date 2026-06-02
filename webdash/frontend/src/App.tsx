import { useCallback, useEffect, useState } from "react";
import { apiGet, StateResp, TOKEN, useStream } from "./api";
import { AgentActivity } from "./components/AgentActivity";
import { AttackGraph } from "./components/AttackGraph";
import { AuditTimeline } from "./components/AuditTimeline";
import { ControlBar } from "./components/ControlBar";
import { CostMitre } from "./components/CostMitre";
import { ModelSelector } from "./components/ModelSelector";

export default function App() {
  const stream = useStream();
  const [state, setState] = useState<StateResp | null>(null);

  const refresh = useCallback(() => {
    apiGet<StateResp>("/api/state").then(setState).catch(() => {});
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
  }, [refresh]);

  const snapshot = state ?? stream.snapshot;
  const eng = snapshot?.engagement;

  if (!TOKEN) {
    return (
      <div className="h-screen flex items-center justify-center px-6">
        <div className="hud border border-redteam/50 bg-surface px-6 py-5 max-w-lg">
          <div className="font-display text-redteam glow uppercase tracking-[0.2em] text-sm mb-2">
            ⚠ no auth token
          </div>
          <p className="text-dim text-xs leading-relaxed">
            Open the URL printed by{" "}
            <code className="text-amber">python main.py dashboard --web</code> — it carries
            the <code className="text-amber">#token=…</code> fragment required for C2 access.
          </p>
        </div>
      </div>
    );
  }

  // staggered boot reveal
  const cell = (i: number) => ({ animationDelay: `${0.06 * i}s` });

  return (
    <div className="h-screen flex flex-col text-[13px]">
      <header className="flex items-center justify-between px-4 py-2 border-b border-line bg-surface/90 animate-flicker">
        <div className="flex items-baseline gap-3">
          <span className="font-display font-700 text-amber glow tracking-[0.3em] text-lg">
            OPENELIA
          </span>
          <span className="font-display text-dim tracking-[0.4em] text-[10px]">// C2 CONSOLE</span>
          <span className="font-mono text-[11px] text-dim ml-2">
            {eng ? (
              <>
                <span className="text-blueteam">{eng.id}</span>
                <span className="text-dim"> ▪ TGT </span>
                <span className="text-redteam">{eng.target}</span>
              </>
            ) : (
              "— no active engagement —"
            )}
          </span>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest">
          <span
            className={`inline-block w-2 h-2 rounded-full ${
              stream.connected ? "bg-phos glow animate-blink" : "bg-dim"
            }`}
          />
          <span className={stream.connected ? "text-phos" : "text-dim"}>
            {stream.connected ? "telemetry live" : "offline"}
          </span>
        </div>
      </header>

      <main className="flex-1 min-h-0 overflow-hidden p-3 grid gap-3 grid-cols-1 lg:grid-cols-4 lg:grid-rows-[auto_minmax(0,1fr)_minmax(0,1fr)]">
        <div className="lg:col-span-4 min-h-0 overflow-hidden animate-boot" style={cell(0)}>
          <ControlBar snapshot={snapshot} onChange={refresh} />
        </div>

        <div className="lg:col-span-1 min-h-0 overflow-hidden animate-boot" style={cell(1)}>
          <AgentActivity liveTasks={stream.tasks} />
        </div>
        <div className="lg:col-span-2 min-h-0 overflow-hidden animate-boot" style={cell(2)}>
          <AttackGraph />
        </div>
        <div className="lg:col-span-1 min-h-0 overflow-hidden animate-boot" style={cell(3)}>
          <AuditTimeline liveAudit={stream.audit} />
        </div>

        <div className="lg:col-span-2 min-h-0 overflow-hidden animate-boot" style={cell(4)}>
          <ModelSelector />
        </div>
        <div className="lg:col-span-2 min-h-0 overflow-hidden animate-boot" style={cell(5)}>
          <CostMitre />
        </div>
      </main>
    </div>
  );
}
