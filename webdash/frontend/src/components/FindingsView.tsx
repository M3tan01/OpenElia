import { useEffect, useState } from "react";
import { apiGet, Finding, StateResp } from "../api";
import { Badge, Panel } from "./Panel";

const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400 border-red-400/60",
  high: "text-orange-400 border-orange-400/60",
  medium: "text-amber border-amber/60",
  low: "text-phos border-phos/60",
  info: "text-dim border-line",
};

function sevClass(sev: string): string {
  return SEV_COLOR[(sev || "").toLowerCase()] ?? "text-dim border-line";
}

function cvssClass(score: number): string {
  if (score >= 9.0) return "text-red-400";
  if (score >= 7.0) return "text-orange-400";
  if (score >= 4.0) return "text-amber";
  return "text-phos";
}

export function FindingsView() {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const load = () =>
      apiGet<StateResp>("/api/state")
        .then((s) => setFindings(s.findings ?? []))
        .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)));
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  return (
    <Panel title="Findings" className="h-full">
      {err && <div className="mb-3"><Badge ok={false}>{err}</Badge></div>}
      {!findings && !err && <div className="text-dim text-xs italic">loading…</div>}
      {findings?.length === 0 && <div className="text-dim text-xs italic">no findings yet</div>}
      <div className="space-y-1.5 overflow-auto scroll-thin">
        {(findings ?? []).map((f, i) => (
          <div key={i} className={`border-l-2 ${sevClass(f.severity)} bg-surface/40 px-3 py-2`}>
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-sm text-slate-200">{f.title}</span>
              <div className="flex items-center gap-2 shrink-0">
                <span className={`font-mono text-[10px] uppercase tracking-wider px-1.5 py-0.5 border ${sevClass(f.severity)}`}>
                  {f.severity || "—"}
                </span>
                {typeof f.cvss_score === "number" && (
                  <span className={`font-mono text-xs font-semibold ${cvssClass(f.cvss_score)}`}>
                    CVSS {f.cvss_score.toFixed(1)}
                  </span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-3 mt-0.5 font-mono text-[11px] text-dim">
              {f.mitre_ttp && <span className="text-amber/70">{f.mitre_ttp}</span>}
              {f.cvss_vector && <span className="truncate">{f.cvss_vector}</span>}
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}
