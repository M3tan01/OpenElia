import { useState } from "react";
import { StateResp, StreamState } from "../api";
import {
  PANEL_BY_ID,
  PANEL_CATALOG,
  PanelCtx,
  spanClass,
} from "../dashboardPanels";
import { useDashboardLayout } from "../useDashboardLayout";

export function C2ConsoleView({
  snapshot,
  stream,
  refresh,
}: {
  snapshot: StateResp | null;
  stream: StreamState;
  refresh: () => void;
}) {
  const { ids, add, remove, move, reset } = useDashboardLayout();
  const [editing, setEditing] = useState(false);

  const ctx: PanelCtx = { snapshot, stream, refresh };
  const cell = (i: number) => ({ animationDelay: `${0.06 * i}s` });

  // Panels available to add = catalog minus what's already shown.
  const hidden = PANEL_CATALOG.filter((p) => !ids.includes(p.id));

  const btn =
    "font-display uppercase tracking-widest text-[10px] px-2 py-1 border transition-colors";

  return (
    <main className="flex-1 min-h-0 overflow-auto scroll-thin p-3 flex flex-col gap-3">
      {/* customize toolbar */}
      <div className="flex items-center gap-2 flex-wrap shrink-0">
        <button
          type="button"
          onClick={() => setEditing((e) => !e)}
          aria-pressed={editing}
          className={`${btn} ${
            editing
              ? "border-amber text-amber glow bg-amber/10"
              : "border-line text-dim hover:text-amber/80"
          }`}
        >
          {editing ? "✓ Done" : "⚙ Customize"}
        </button>

        {editing && (
          <>
            {hidden.length > 0 ? (
              <select
                value=""
                onChange={(e) => { if (e.target.value) add(e.target.value); }}
                aria-label="Add panel to dashboard"
                className="bg-void border border-line px-2 py-1 text-[11px] font-mono text-slate-200 focus:border-amber focus:outline-none"
              >
                <option value="">+ add panel…</option>
                {hidden.map((p) => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </select>
            ) : (
              <span className="font-mono text-[10px] text-dim italic">all panels shown</span>
            )}
            <button
              type="button"
              onClick={reset}
              className={`${btn} border-line text-dim hover:text-amber/80`}
            >
              ↺ Reset
            </button>
            <span className="font-mono text-[10px] text-dim italic ml-1">
              add / remove / reorder — saved to this browser
            </span>
          </>
        )}
      </div>

      {ids.length === 0 && (
        <div className="font-mono text-xs text-dim italic">
          empty dashboard — use ⚙ Customize → “add panel” to compose your view.
        </div>
      )}

      {/* panel grid */}
      <div className="grid gap-3 grid-cols-1 lg:grid-cols-4 auto-rows-[minmax(0,auto)]">
        {ids.map((id, i) => {
          const def = PANEL_BY_ID[id];
          if (!def) return null;
          // full-width panels (Control) size to content; the rest get a fixed
          // viewport so their internal scroll regions behave in the grid.
          const heightCls = def.span === "full" ? "" : "h-[340px]";
          return (
            <div
              key={id}
              className={`${spanClass(def.span)} ${heightCls} min-h-0 overflow-hidden animate-boot relative`}
              style={cell(i)}
            >
              {editing && (
                <div className="absolute top-1.5 right-1.5 z-10 flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => move(id, -1)}
                    disabled={i === 0}
                    title="move earlier"
                    className="font-mono text-[11px] w-6 h-6 border border-line bg-void/90 text-dim hover:text-amber disabled:opacity-30"
                  >
                    ↑
                  </button>
                  <button
                    type="button"
                    onClick={() => move(id, 1)}
                    disabled={i === ids.length - 1}
                    title="move later"
                    className="font-mono text-[11px] w-6 h-6 border border-line bg-void/90 text-dim hover:text-amber disabled:opacity-30"
                  >
                    ↓
                  </button>
                  <button
                    type="button"
                    onClick={() => remove(id)}
                    title={`remove ${def.label}`}
                    className="font-mono text-[11px] w-6 h-6 border border-redteam/60 bg-void/90 text-redteam hover:bg-redteam/15"
                  >
                    ✕
                  </button>
                </div>
              )}
              {def.render(ctx)}
            </div>
          );
        })}
      </div>
    </main>
  );
}
