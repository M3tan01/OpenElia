import { useEffect, useMemo, useState } from "react";
import { apiGet, AuditEvent, AuditResp } from "../api";
import { Panel } from "./Panel";

const STATUS_COLOR: Record<string, string> = {
  LLM_CALL: "text-sky-400",
  LOOP_DETECTED: "text-amber-400",
  AUTHORIZED: "text-emerald-400",
  DENIED: "text-rose-400",
  ERROR: "text-rose-400",
  LOCKED: "text-amber-300",
  UNLOCKED: "text-emerald-300",
};

export function AuditTimeline({ liveAudit }: { liveAudit: AuditEvent[] }) {
  const [seed, setSeed] = useState<AuditEvent[]>([]);
  const [chainStatus, setChainStatus] = useState("ok");
  const [chainMsg, setChainMsg] = useState("");
  const [filter, setFilter] = useState("");

  useEffect(() => {
    apiGet<AuditResp>("/api/audit?limit=200")
      .then((r) => { setSeed([...r.events].reverse()); setChainStatus(r.chain_status); setChainMsg(r.chain_msg); })
      .catch(() => {});
  }, []);

  // ok → green, legacy → amber (unverifiable prefix, not an alarm), tampered → red
  const chainBadge =
    chainStatus === "tampered"
      ? { cls: "border-redteam/60 text-redteam glow", label: "TAMPERED" }
      : chainStatus === "legacy"
      ? { cls: "border-amber/60 text-amber", label: "legacy" }
      : { cls: "border-phos/50 text-phos", label: "chain ok" };

  const events = useMemo(() => {
    const all = [...liveAudit, ...seed];
    return filter ? all.filter((e) => e.status === filter) : all;
  }, [liveAudit, seed, filter]);

  const statuses = useMemo(
    () => Array.from(new Set([...liveAudit, ...seed].map((e) => e.status))),
    [liveAudit, seed]
  );

  return (
    <Panel
      title="Audit Timeline"
      right={
        <div className="flex items-center gap-2">
          <span
            title={chainMsg}
            className={`font-mono text-[10px] px-2 py-0.5 border uppercase tracking-wider ${chainBadge.cls}`}
          >
            {chainBadge.label}
          </span>
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="bg-void border border-line text-xs px-1 py-0.5 text-slate-300 font-mono"
          >
            <option value="">all</option>
            {statuses.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      }
    >
      <div className="space-y-0.5 font-mono text-[11px]">
        {events.map((e, i) => (
          <div key={i} className="flex gap-2">
            <span className="text-slate-600 shrink-0">{(e.timestamp || "").slice(11, 19)}</span>
            <span className={`shrink-0 w-28 ${STATUS_COLOR[e.status] ?? "text-slate-400"}`}>{e.status}</span>
            <span className="text-slate-400 shrink-0">{e.source}</span>
            <span className="text-slate-500 truncate">{e.reason}</span>
          </div>
        ))}
        {events.length === 0 && <div className="text-slate-600 italic">no events</div>}
      </div>
    </Panel>
  );
}
