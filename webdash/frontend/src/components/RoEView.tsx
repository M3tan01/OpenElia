import { useEffect, useState } from "react";
import { apiGet, RoEResp, ScopeCheckResp } from "../api";
import { Badge, Panel } from "./Panel";

function ScopeCheck() {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<ScopeCheckResp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function check() {
    const t = target.trim();
    if (!t || pending) return;
    setPending(true); setErr(null); setResult(null);
    try {
      setResult(await apiGet<ScopeCheckResp>(`/api/scope/check?target=${encodeURIComponent(t)}`));
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setPending(false); }
  }

  return (
    <section>
      <h3 className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-1.5">
        Scope Check
      </h3>
      <div className="flex gap-2">
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") check(); }}
          placeholder="host or CIDR"
          className="flex-1 bg-void border border-line px-2 py-1 text-xs font-mono text-slate-200 focus:border-amber focus:outline-none"
        />
        <button
          type="button"
          onClick={check}
          disabled={pending}
          className="font-display uppercase tracking-widest text-xs px-3 py-1 border border-amber text-amber glow disabled:opacity-40"
        >
          {pending ? "···" : "check"}
        </button>
      </div>
      {err && <div className="mt-1.5"><Badge ok={false}>{err}</Badge></div>}
      {result && (
        <div className="mt-1.5 font-mono text-[11px]">
          <span className={result.allowed ? "text-phos" : "text-rose-400"}>
            {result.allowed ? "✓ in scope" : "✗ out of scope / blacklisted"}
          </span>
          {result.quiet_hours_active && (
            <span className="text-amber/70"> · quiet hours active</span>
          )}
        </div>
      )}
    </section>
  );
}

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

          <ScopeCheck />
        </div>
      )}
    </Panel>
  );
}
