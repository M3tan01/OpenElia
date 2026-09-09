import { useState } from "react";
import { getCampaignTrend, CampaignTrendResp, TrendSnapshot } from "../api";
import { Badge, Panel } from "./Panel";

const RUNG_ORDER = ["PREVENTED", "ALERTED", "DETECTED", "LOGGED", "MISSED", "PENDING"] as const;
const RUNG_TEXT: Record<string, string> = {
  PREVENTED: "text-phos", ALERTED: "text-phos", DETECTED: "text-amber",
  LOGGED: "text-amber", MISSED: "text-red-400", PENDING: "text-slate-400",
};

function pctClass(pct: number): string {
  if (pct >= 80) return "text-phos";
  if (pct >= 50) return "text-amber";
  return "text-red-400";
}

function SnapshotRow({ snap, prevPct }: { snap: TrendSnapshot; prevPct: number | null }) {
  const delta = prevPct == null ? null : Math.round((snap.coverage_pct - prevPct) * 10) / 10;
  return (
    <div className="border-l-2 border-slate-500/40 bg-surface/40 px-3 py-1.5">
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-xs text-dim">{snap.ts}</span>
        <span className="font-mono text-sm">
          <span className={pctClass(snap.coverage_pct)}>{snap.coverage_pct.toFixed(0)}%</span>
          {delta != null && (
            <span className={`ml-2 text-[10px] ${delta >= 0 ? "text-phos" : "text-red-400"}`}>
              {delta >= 0 ? "▲" : "▼"} {Math.abs(delta)}
            </span>
          )}
        </span>
      </div>
      <div className="mt-1 w-full h-1.5 bg-slate-700/40 overflow-hidden">
        <div
          className={`h-full ${pctClass(snap.coverage_pct).replace("text-", "bg-")}`}
          style={{ width: `${Math.max(0, Math.min(100, snap.coverage_pct))}%` }}
        />
      </div>
      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[10px] uppercase tracking-wider">
        {RUNG_ORDER.map((r) => (
          <span key={r} className={RUNG_TEXT[r]}>{r} {snap.rung_counts[r] ?? 0}</span>
        ))}
      </div>
      {snap.ttps.length > 0 && (
        <div className="mt-1.5 space-y-0.5">
          {snap.ttps.map((t, i) => (
            <div key={`${t.ttp}-${i}`} className="flex items-center justify-between gap-2 font-mono text-[11px]">
              <span className="text-amber/80">{t.ttp}</span>
              <span className={RUNG_TEXT[t.rung] ?? "text-slate-400"}>
                {t.rung} · {t.time_to_detect_s == null ? "—" : `${t.time_to_detect_s}s`}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function CampaignTrendView() {
  const [campaignId, setCampaignId] = useState("");
  const [data, setData] = useState<CampaignTrendResp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load(e: React.FormEvent) {
    e.preventDefault();
    if (!campaignId.trim()) return;
    setLoading(true); setErr(null);
    try {
      setData(await getCampaignTrend(campaignId.trim()));
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : String(ex));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Panel title="Campaign Trend" className="h-full">
      <form onSubmit={load} className="mb-3 flex gap-2">
        <input
          value={campaignId}
          onChange={(e) => setCampaignId(e.target.value)}
          placeholder="campaign id"
          className="flex-1 bg-surface/60 border border-slate-500/40 px-2 py-1 font-mono text-sm text-slate-200"
        />
        <button type="submit" className="px-3 py-1 font-mono text-sm border border-phos/60 text-phos">
          load
        </button>
      </form>
      {err && <div className="mb-3"><Badge ok={false}>{err}</Badge></div>}
      {loading && <div className="text-dim text-xs italic">loading…</div>}
      {data && data.snapshots.length === 0 && (
        <div className="text-dim text-xs italic">no snapshots for this campaign</div>
      )}
      <div className="space-y-1">
        {data?.snapshots.map((snap, i) => (
          <SnapshotRow
            key={snap.ts}
            snap={snap}
            prevPct={i === 0 ? null : data.snapshots[i - 1].coverage_pct}
          />
        ))}
      </div>
    </Panel>
  );
}
