import { useEffect, useState } from "react";
import { apiGet, apiPost, ActorResp, ForgeResp } from "../api";
import { Badge, Panel } from "./Panel";

type Tier = "local" | "expensive";

export function AdversaryForgeView() {
  const [actors, setActors] = useState<ActorResp[] | null>(null);
  const [actor, setActor] = useState("");
  const [tier, setTier] = useState<Tier>("local");
  const [autoCommit, setAutoCommit] = useState(false);
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<ForgeResp | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    apiGet<ActorResp[]>("/api/actors")
      .then((a) => { setActors(a); if (a.length) setActor(a[0]); })
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);

  async function forge() {
    if (!actor || pending) return;
    setPending(true); setErr(null); setResult(null);
    try {
      const r = await apiPost<ForgeResp>("/api/forge", {
        actor, brain_tier: tier, auto_commit: autoCommit, confirm: true,
      });
      setResult(r);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setPending(false); }
  }

  return (
    <Panel title="Adversary Forge" className="h-full">
      <div className="flex flex-col h-full">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 flex-1 min-h-0 overflow-auto">
        {/* left: config workspace */}
        <div className="space-y-3">
          <div className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70">
            Configuration
          </div>
          <select
            value={actor}
            onChange={(e) => setActor(e.target.value)}
            className="w-full bg-void border border-line px-2 py-1 text-xs font-mono text-slate-200 focus:border-amber focus:outline-none"
          >
            {(actors ?? []).map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
          <div className="flex gap-2">
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
          <label className="flex items-center gap-2 text-xs font-mono text-dim">
            <input type="checkbox" checked={autoCommit}
                   onChange={(e) => setAutoCommit(e.target.checked)} />
            auto-commit to adversaries/
          </label>
          {err && <Badge ok={false}>{err}</Badge>}
        </div>

        {/* right: verification pipeline stream */}
        <div className="border border-line bg-surface/50 p-3 overflow-auto scroll-thin">
          <div className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-2">
            Pipeline
          </div>
          {!result && <div className="text-dim text-xs italic">no run yet</div>}
          {result && (
            <div className="space-y-1">
              {result.profile.preferred_ttps.map((t) => (
                <div key={t} className="font-mono text-xs px-2 py-0.5 border-l-2 border-phos text-phos">
                  ✓ {t}
                </div>
              ))}
              {result.omitted.map((d) => (
                <div key={d.t_code}
                     className="font-mono text-[11px] px-2 py-0.5 border-l-2 border-amber/40 text-dim line-through opacity-60">
                  ✗ {d.t_code} — {d.reason}
                </div>
              ))}
              {result.saved_path && (
                <div className="mt-2 text-[11px] font-mono text-phos">saved: {result.saved_path}</div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* footer security anchor — pinned to panel bottom */}
      <div className="mt-3 border-t border-line pt-2 flex items-center justify-between shrink-0">
        <span className="text-[11px] font-mono text-dim">
          Forge generates a profile only — running it still requires the gated /run path.
        </span>
        <button
          type="button"
          onClick={forge}
          disabled={!actor || pending}
          className="font-display uppercase tracking-widest bg-amber/15 border border-amber text-amber glow text-xs px-4 py-1 disabled:opacity-40 hover:bg-amber/25"
        >
          {pending ? "···" : "▶ Forge Profile"}
        </button>
      </div>
      </div>
    </Panel>
  );
}
