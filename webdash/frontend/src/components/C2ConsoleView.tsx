import { StateResp, StreamState } from "../api";
import { AgentActivity } from "./AgentActivity";
import { AttackGraph } from "./AttackGraph";
import { AuditTimeline } from "./AuditTimeline";
import { ControlBar } from "./ControlBar";
import { CostMitre } from "./CostMitre";
import { ModelSelector } from "./ModelSelector";

export function C2ConsoleView({
  snapshot,
  stream,
  refresh,
}: {
  snapshot: StateResp | null;
  stream: StreamState;
  refresh: () => void;
}) {
  // staggered boot reveal
  const cell = (i: number) => ({ animationDelay: `${0.06 * i}s` });

  return (
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
  );
}
