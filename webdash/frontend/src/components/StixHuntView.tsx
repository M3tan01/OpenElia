import { useState } from "react";
import { apiPost, RunResp, StixBrief } from "../api";
import { Badge, Panel } from "./Panel";

export function StixHuntView() {
  const [fileName, setFileName] = useState<string | null>(null);
  const [brief, setBrief] = useState<StixBrief | null>(null);
  const [target, setTarget] = useState("");
  const [parsing, setParsing] = useState(false);
  const [running, setRunning] = useState(false);
  const [run, setRun] = useState<RunResp | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    setFileName(f.name); setErr(null); setBrief(null); setRun(null); setParsing(true);
    try {
      const content = await f.text();
      setBrief(await apiPost<StixBrief>("/api/stix/parse", { content }));
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setParsing(false); }
  }

  async function runHunt() {
    if (!brief || running) return;
    setRunning(true); setErr(null); setRun(null);
    try {
      const r = await apiPost<RunResp>("/api/run/blue", {
        task: brief.hunt_task,
        target: target.trim() || null,
        brain_tier: "local",
        confirm: true,
      });
      setRun(r);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setRunning(false); }
  }

  const c = brief?.counts ?? {};

  return (
    <Panel title="Threat Hunt (STIX)" className="h-full">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 h-full">
        {/* left: upload + summary */}
        <div className="space-y-3 overflow-auto scroll-thin">
          <div className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70">
            STIX Bundle
          </div>
          <label className="block border border-dashed border-line hover:border-amber/50 px-3 py-4 text-center cursor-pointer">
            <input type="file" accept=".json,application/json" onChange={onFile} className="hidden" />
            <span className="font-mono text-xs text-dim">
              {fileName ? fileName : "click to choose a STIX 2.x .json bundle"}
            </span>
          </label>
          {parsing && <div className="text-dim text-xs italic">parsing…</div>}
          {err && <Badge ok={false}>{err}</Badge>}

          {brief && (
            <div className="grid grid-cols-4 gap-2 text-center">
              {(["iocs", "ttps", "actors", "malware"] as const).map((k) => (
                <div key={k} className="border border-line bg-surface/40 py-2">
                  <div className="font-mono text-lg text-amber glow">{c[k] ?? 0}</div>
                  <div className="font-display text-[9px] uppercase tracking-wider text-dim">{k}</div>
                </div>
              ))}
            </div>
          )}

          {brief && brief.actors.length > 0 && (
            <div className="font-mono text-[11px] text-dim">
              <span className="text-amber/70">actors:</span> {brief.actors.join(", ")}
            </div>
          )}
          {brief && brief.ttps.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {brief.ttps.map((t) => (
                <span key={t} className="font-mono text-[10px] px-1.5 py-0.5 border border-amber/40 text-amber/80">{t}</span>
              ))}
            </div>
          )}
        </div>

        {/* right: IOC preview */}
        <div className="border border-line bg-surface/50 p-3 overflow-auto scroll-thin">
          <div className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-2">
            Indicators
          </div>
          {!brief && <div className="text-dim text-xs italic">upload a bundle to preview IOCs</div>}
          {brief?.iocs.length === 0 && <div className="text-dim text-xs italic">no IOCs in bundle</div>}
          <div className="space-y-0.5">
            {(brief?.iocs ?? []).map((ioc, i) => (
              <div key={i} className="flex items-center gap-2 font-mono text-[11px]">
                <span className="text-phos/80 uppercase w-14 shrink-0">{ioc.type}</span>
                <span className="text-slate-300 truncate">{ioc.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* footer: target + run */}
      <div className="mt-3 border-t border-line pt-2 flex items-center justify-between gap-3">
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="optional hunt target/scope (host or CIDR)"
          className="flex-1 bg-void border border-line px-2 py-1 text-xs font-mono text-slate-200 focus:border-amber focus:outline-none"
        />
        {run && <span className="text-[11px] font-mono text-phos shrink-0">launched: {run.run_id}</span>}
        <button
          type="button"
          onClick={runHunt}
          disabled={!brief || running}
          className="font-display uppercase tracking-widest bg-amber/15 border border-amber text-amber glow text-xs px-4 py-1 disabled:opacity-40 hover:bg-amber/25 shrink-0"
        >
          {running ? "···" : "▶ Run Hunt"}
        </button>
      </div>
    </Panel>
  );
}
