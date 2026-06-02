import { useEffect, useState } from "react";
import { apiGet, EngagementResp } from "../api";
import { Badge, Panel } from "./Panel";

const readOnlyBadge = (
  <span className="font-mono text-[10px] px-2 py-0.5 border border-amber/40 text-amber/60 uppercase tracking-wider">
    read-only
  </span>
);

function LockTag() {
  return (
    <span className="font-mono text-[9px] px-1.5 py-0.5 border border-redteam/50 text-redteam uppercase tracking-wider">
      LOCKED
    </span>
  );
}

function PhaseTag({ phase }: { phase: string }) {
  return (
    <span className="font-mono text-[10px] text-dim/70 border border-line px-1.5 py-0.5 uppercase tracking-wide">
      {phase}
    </span>
  );
}

export function EngagementsView() {
  const [data, setData] = useState<EngagementResp[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    apiGet<EngagementResp[]>("/api/engagements")
      .then(setData)
      .catch((e: Error) => setErr(e.message));
  }, []);

  return (
    <Panel title="Sessions" right={readOnlyBadge} className="h-full">
      {err && (
        <div className="mb-3">
          <Badge ok={false}>{err}</Badge>
        </div>
      )}
      {!data && !err && (
        <div className="text-dim text-xs italic">loading…</div>
      )}
      {data && data.length === 0 && (
        <div className="text-dim/50 text-xs italic">— no engagements —</div>
      )}
      {data && data.length > 0 && (
        <div className="space-y-2">
          {data.map((eng) => (
            <div
              key={eng.id}
              className={`border px-3 py-2.5 flex flex-col gap-1.5 ${
                eng.is_active
                  ? "border-amber/50 bg-amber/5"
                  : "border-line bg-surface/40"
              }`}
            >
              {/* header row */}
              <div className="flex items-center gap-2 flex-wrap">
                <span
                  className={`font-mono text-xs font-semibold ${
                    eng.is_active ? "text-amber glow" : "text-slate-300"
                  }`}
                >
                  {eng.id}
                </span>
                {eng.is_active && <Badge ok={true}>ACTIVE</Badge>}
                {eng.is_locked && <LockTag />}
              </div>

              {/* detail row */}
              <div className="flex items-center gap-4 flex-wrap">
                <span className="font-display text-[10px] uppercase tracking-[0.15em] text-dim">
                  TGT&nbsp;
                  <span className="font-mono text-xs text-slate-300 normal-case tracking-normal">
                    {eng.target}
                  </span>
                </span>

                {eng.started && (
                  <span className="font-display text-[10px] uppercase tracking-[0.15em] text-dim">
                    START&nbsp;
                    <span className="font-mono text-xs text-slate-300 normal-case tracking-normal">
                      {eng.started}
                    </span>
                  </span>
                )}

                {eng.current_phase && (
                  <span className="font-display text-[10px] uppercase tracking-[0.15em] text-dim flex items-center gap-1.5">
                    PHASE&nbsp;
                    <PhaseTag phase={eng.current_phase} />
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
