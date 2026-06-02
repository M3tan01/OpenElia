import { useEffect, useState } from "react";
import { apiGet, RoEResp } from "../api";
import { Badge, Panel } from "./Panel";

function ItemList({ items }: { items: string[] }) {
  if (items.length === 0) {
    return <span className="text-dim/50 italic text-xs">— none —</span>;
  }
  return (
    <ul className="space-y-0.5">
      {items.map((item) => (
        <li key={item} className="font-mono text-xs text-slate-300">
          {item}
        </li>
      ))}
    </ul>
  );
}

function renderQuietHours(qh: RoEResp["quiet_hours"]): string {
  if (qh === null || qh === undefined) return "— not set —";
  if (typeof qh === "string") return qh;
  const { start, end } = qh;
  if (start && end) return `${start} – ${end}`;
  if (start) return `from ${start}`;
  if (end) return `until ${end}`;
  return "— not set —";
}

export function RoEView() {
  const [data, setData] = useState<RoEResp | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    apiGet<RoEResp>("/api/roe")
      .then(setData)
      .catch((e: Error) => setErr(e.message));
  }, []);

  const readOnlyBadge = (
    <span className="font-mono text-[10px] px-2 py-0.5 border border-amber/40 text-amber/60 uppercase tracking-wider">
      read-only
    </span>
  );

  return (
    <Panel title="RoE / Scope" right={readOnlyBadge} className="h-full">
      {err && (
        <div className="mb-3">
          <Badge ok={false}>{err}</Badge>
        </div>
      )}
      {!data && !err && (
        <div className="text-dim text-xs italic">loading…</div>
      )}
      {data && (
        <div className="space-y-4 text-xs">
          <section>
            <h3 className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-1.5">
              Authorized Subnets
            </h3>
            <ItemList items={data.authorized_subnets} />
          </section>

          <section>
            <h3 className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-1.5">
              Blacklisted IPs
            </h3>
            <ItemList items={data.blacklisted_ips} />
          </section>

          <section>
            <h3 className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-1.5">
              Prohibited Tools
            </h3>
            <ItemList items={data.prohibited_tools} />
          </section>

          <section>
            <h3 className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-1.5">
              Quiet Hours
            </h3>
            <span className="font-mono text-xs text-slate-300">
              {renderQuietHours(data.quiet_hours)}
            </span>
          </section>
        </div>
      )}
    </Panel>
  );
}
