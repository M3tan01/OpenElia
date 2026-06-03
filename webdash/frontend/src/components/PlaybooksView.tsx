import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, PlaybookSummary, RunResp } from "../api";
import { Badge, Panel } from "./Panel";
import { PlaybookCreateForm } from "./PlaybookCreateForm";

type Tier = "local" | "expensive";

export function PlaybooksView() {
  const [playbooks, setPlaybooks] = useState<PlaybookSummary[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [target, setTarget] = useState("");
  const [tier, setTier] = useState<Tier>("local");
  const [pending, setPending] = useState(false);
  const [run, setRun] = useState<RunResp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback((select?: string) => {
    apiGet<PlaybookSummary[]>("/api/playbooks")
      .then((p) => {
        setPlaybooks(p);
        setSelected((cur) => select ?? cur ?? (p.length ? p[0].name : null));
      })
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);

  useEffect(() => { load(); }, [load]);

  const pb = (playbooks ?? []).find((p) => p.name === selected) ?? null;
  const targetRequired = !!pb?.variables?.target?.required;

  async function launch() {
    if (!pb || pending) return;
    if (targetRequired && !target.trim()) {
      setErr("target is required for this playbook");
      return;
    }
    setPending(true); setErr(null); setRun(null);
    try {
      const r = await apiPost<RunResp>("/api/run/playbook", {
        name: pb.name,
        target: target.trim() || null,
        stealth: pb.stealth,
        brain_tier: tier,
        confirm: true,
      });
      setRun(r);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setPending(false); }
  }

  return (
    <Panel title="Playbooks" className="h-full">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 h-full">
        {/* left: playbook catalogue */}
        <div className="space-y-2 overflow-auto scroll-thin">
          <div className="flex items-center justify-between">
            <div className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70">
              Catalogue
            </div>
            <button
              type="button"
              onClick={() => { setCreating(true); setRun(null); setErr(null); }}
              className="font-mono text-[11px] text-amber hover:glow"
            >
              ＋ New
            </button>
          </div>
          {!playbooks && !err && <div className="text-dim text-xs italic">loading…</div>}
          {playbooks?.length === 0 && (
            <div className="text-dim text-xs italic">no playbooks found</div>
          )}
          {(playbooks ?? []).map((p) => {
            const active = p.name === selected;
            return (
              <button
                key={p.name}
                type="button"
                onClick={() => { setSelected(p.name); setRun(null); setErr(null); }}
                className={`w-full text-left px-3 py-2 border transition-colors ${
                  active ? "border-amber bg-amber/10" : "border-line hover:border-amber/40"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm text-slate-200">{p.name}</span>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-amber/70">
                    {p.domain}{p.passive ? " · passive" : ""}{p.stealth ? " · stealth" : ""}
                  </span>
                </div>
                <div className="font-mono text-[11px] text-dim mt-0.5">{p.description}</div>
              </button>
            );
          })}
        </div>

        {/* right: create form OR detail + launch */}
        {creating ? (
          <PlaybookCreateForm
            onCreated={() => { setCreating(false); load(); }}
            onCancel={() => setCreating(false)}
          />
        ) : (
        <div className="border border-line bg-surface/50 p-3 overflow-auto scroll-thin flex flex-col">
          <div className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-2">
            {pb ? `${pb.name} — flow` : "Detail"}
          </div>
          {!pb && <div className="text-dim text-xs italic">select a playbook</div>}
          {pb && (
            <>
              <div className="space-y-1 mb-3">
                {pb.phases.map((ph, i) => (
                  <div key={ph.name} className="font-mono text-[11px] px-2 py-1 border-l-2 border-phos/60 text-slate-300">
                    <span className="text-phos">{i + 1}. {ph.name}</span>
                    {ph.tools.length > 0 && (
                      <span className="text-dim"> — {ph.tools.join(", ")}</span>
                    )}
                    {ph.post_analysis && (
                      <div className="text-dim/80 mt-0.5">{ph.post_analysis}</div>
                    )}
                  </div>
                ))}
              </div>

              <label className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-1">
                Target {targetRequired && <span className="text-phos">*</span>}
              </label>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="host or CIDR (e.g. 10.0.0.0/24)"
                className="w-full bg-void border border-line px-2 py-1 text-xs font-mono text-slate-200 focus:border-amber focus:outline-none mb-2"
              />
              <div className="flex gap-2 mb-2">
                {(["local", "expensive"] as Tier[]).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setTier(t)}
                    className={`font-display uppercase tracking-widest text-xs px-3 py-1 border ${
                      tier === t ? "border-amber text-amber glow" : "border-line text-dim"
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
              {err && <div className="mb-2"><Badge ok={false}>{err}</Badge></div>}
              {run && (
                <div className="mb-2 text-[11px] font-mono text-phos">
                  launched: {run.run_id} ({run.status})
                </div>
              )}
            </>
          )}
        </div>
        )}
      </div>

      {/* footer launch anchor */}
      {!creating && (
        <div className="mt-3 border-t border-line pt-2 flex items-center justify-between">
          <span className="text-[11px] font-mono text-dim">
            Offensive playbooks pass the RoE scope gate and kill-switch check before launch.
          </span>
          <button
            type="button"
            onClick={launch}
            disabled={!pb || pending}
            className="font-display uppercase tracking-widest bg-amber/15 border border-amber text-amber glow text-xs px-4 py-1 disabled:opacity-40 hover:bg-amber/25"
          >
            {pending ? "···" : "▶ Run Playbook"}
          </button>
        </div>
      )}
    </Panel>
  );
}
