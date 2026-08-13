import { apiGet, CoverageResp, CoverageTtp } from "../api";
import { usePoll } from "../usePoll";
import { Badge, Panel } from "./Panel";

// Coverage headline colour tiers — red team caught / not by blue team.
function pctClass(pct: number): string {
  if (pct >= 80) return "text-phos";
  if (pct >= 50) return "text-amber";
  return "text-red-400";
}

const SECTIONS: { key: keyof Pick<CoverageResp, "caught" | "pending" | "missed">; icon: string; label: string; rowClass: string }[] = [
  { key: "caught",  icon: "✅", label: "caught",  rowClass: "border-phos/60 text-phos" },
  { key: "pending", icon: "⏳", label: "pending", rowClass: "border-amber/60 text-amber" },
  { key: "missed",  icon: "❌", label: "missed",  rowClass: "border-red-400/60 text-red-400" },
];

function TtpRow({ entry, rowClass, tag }: { entry: CoverageTtp; rowClass: string; tag: string }) {
  return (
    <div className={`flex items-center justify-between gap-2 border-l-2 ${rowClass} bg-surface/40 px-3 py-1.5`}>
      <span className="font-mono text-sm">
        <span className="text-amber/80">{entry.ttp}</span>
        <span className="text-slate-200 ml-2">{entry.title}</span>
      </span>
      <span className="font-mono text-[10px] uppercase tracking-wider shrink-0">{tag}</span>
    </div>
  );
}

export function PurpleCoverageView() {
  const { data, error: err } = usePoll<CoverageResp>(
    () => apiGet<CoverageResp>("/api/coverage"),
    5000,
  );

  const total = data ? data.caught.length + data.pending.length + data.missed.length : 0;

  const headline = data ? (
    <span className={`font-mono text-lg font-semibold ${pctClass(data.coverage_pct)}`}>
      {data.coverage_pct.toFixed(0)}%
    </span>
  ) : undefined;

  return (
    <Panel title="Purple Coverage" right={headline} className="h-full">
      {err && <div className="mb-3"><Badge ok={false}>{err}</Badge></div>}
      {!data && !err && <div className="text-dim text-xs italic">loading…</div>}
      {data && total === 0 && (
        <div className="text-dim text-xs italic">awaiting detections</div>
      )}
      <div className="space-y-3">
        {data && SECTIONS.map(({ key, icon, label, rowClass }) => {
          const entries = data[key];
          if (entries.length === 0) return null;
          return (
            <div key={key} className="space-y-1">
              <div className="font-display uppercase tracking-wider text-dim text-[11px]">
                {icon} {label} · {entries.length}
              </div>
              {entries.map((e, i) => (
                <TtpRow key={`${e.ttp}-${i}`} entry={e} rowClass={rowClass} tag={label} />
              ))}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}
