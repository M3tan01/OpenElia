import { useState } from "react";
import { apiGet, apiPost, EngagementResp } from "../api";
import { Badge, Panel } from "./Panel";
import { usePoll } from "../usePoll";

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

type TerminateResp = {
  terminated: boolean;
  engagement_id: string;
  cleanup: { executed: number; refused: number; failed: number; pending: number };
};

export function EngagementsView() {
  const { data, error: err, refresh } = usePoll<EngagementResp[]>(
    () => apiGet<EngagementResp[]>("/api/engagements"),
    5000,
  );
  const [busyId, setBusyId] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);

  async function terminate(eng: EngagementResp) {
    if (
      !window.confirm(
        `Terminate session ${eng.id} (target ${eng.target})?\n\n` +
          "This ends the engagement and fires its rollback queue (undo of any " +
          "persistence/payloads, LIFO). History is preserved — data is NOT deleted."
      )
    )
      return;
    setBusyId(eng.id);
    setNotice(null);
    try {
      const r = await apiPost<TerminateResp>(
        `/api/engagements/${encodeURIComponent(eng.id)}/terminate`,
        { confirm: true }
      );
      const c = r.cleanup;
      setNotice({
        ok: true,
        text: `terminated ${r.engagement_id} — rollback: ${c.executed} undone, ${c.refused} refused, ${c.failed} failed, ${c.pending} pending`,
      });
      refresh();
    } catch (e: unknown) {
      setNotice({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Panel title="Sessions" className="h-full" right={err ? <Badge ok={false}>offline</Badge> : undefined}>
      {notice && (
        <div className="mb-3">
          <Badge ok={notice.ok}>{notice.text}</Badge>
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
                {eng.is_active && (
                  <button
                    type="button"
                    onClick={() => terminate(eng)}
                    disabled={busyId === eng.id}
                    title="Gracefully end this session and roll back its offensive actions"
                    className="ml-auto font-display uppercase tracking-widest text-[10px] px-2 py-0.5 border border-redteam/70 text-redteam hover:bg-redteam/10 disabled:opacity-40"
                  >
                    {busyId === eng.id ? "···" : "⏹ Terminate"}
                  </button>
                )}
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
