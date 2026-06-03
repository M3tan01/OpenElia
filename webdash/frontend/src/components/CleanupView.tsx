import { useEffect, useState } from "react";
import { apiGet, CleanupAction } from "../api";
import { Badge, Panel } from "./Panel";

export function CleanupView() {
  const [actions, setActions] = useState<CleanupAction[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const load = () =>
      apiGet<CleanupAction[]>("/api/cleanup")
        .then(setActions)
        .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)));
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  const note = (
    <span className="font-mono text-[10px] px-2 py-0.5 border border-amber/40 text-amber/60 uppercase tracking-wider">
      runs on lock
    </span>
  );

  return (
    <Panel title="Rollback Queue" right={note} className="h-full">
      {err && <div className="mb-3"><Badge ok={false}>{err}</Badge></div>}
      {!actions && !err && <div className="text-dim text-xs italic">loading…</div>}
      {actions?.length === 0 && (
        <div className="text-dim text-xs italic">no pending rollback actions</div>
      )}
      <div className="space-y-1.5 overflow-auto scroll-thin">
        {(actions ?? []).map((a) => (
          <div key={a.id} className="border-l-2 border-amber/50 bg-surface/40 px-3 py-2">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-sm text-slate-200">{a.description || a.target}</span>
              <span className="font-mono text-[10px] uppercase tracking-wider text-amber/70 shrink-0">
                {a.source}
              </span>
            </div>
            <div className="font-mono text-[11px] text-dim mt-0.5">target: {a.target}</div>
            <div className="font-mono text-[11px] text-dim/80 mt-0.5 truncate">↩ {a.undo_command}</div>
          </div>
        ))}
      </div>
      <div className="mt-3 border-t border-line pt-2">
        <span className="text-[11px] font-mono text-dim">
          Undos fire LIFO on kill-switch (lock), each through the RoE + firewall gate. Crash-recovered
          entries without a callable stay pending for manual review.
        </span>
      </div>
    </Panel>
  );
}
