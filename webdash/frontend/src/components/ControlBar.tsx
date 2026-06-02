import { useState } from "react";
import { apiPost, StateResp } from "../api";
import { Panel } from "./Panel";

type Domain = "red" | "blue" | "purple";

export function ControlBar({ snapshot, onChange }: { snapshot: StateResp | null; onChange: () => void }) {
  const [domain, setDomain] = useState<Domain>("red");
  const [target, setTarget] = useState("");
  const [task, setTask] = useState("");
  const [stealth, setStealth] = useState(false);
  const [brainTier, setBrainTier] = useState("local");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [pending, setPending] = useState<null | "run" | "lock" | "unlock">(null);

  const locked = !!snapshot?.engagement?.is_locked;

  async function run() {
    if (!window.confirm(`Launch ${domain.toUpperCase()} op${target ? ` against ${target}` : ""}? This executes real agents.`)) return;
    setPending("run");
    setMsg(null);
    try {
      const body: Record<string, unknown> = { task: task || undefined, brain_tier: brainTier, confirm: true };
      if (domain !== "blue") { body.target = target; body.stealth = stealth; }
      else { body.target = target || undefined; }
      const r = await apiPost<{ run_id: string }>(`/api/run/${domain}`, body);
      setMsg({ ok: true, text: `started run ${r.run_id}` });
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
    } finally {
      setPending(null);
    }
  }

  async function toggleLock(lock: boolean) {
    if (!window.confirm(lock ? "Engage kill-switch? Halts all agent execution." : "Release kill-switch?")) return;
    setPending(lock ? "lock" : "unlock");
    try {
      await apiPost(`/api/${lock ? "lock" : "unlock"}`, { confirm: true });
      setMsg({ ok: true, text: lock ? "kill-switch engaged" : "kill-switch released" });
      onChange();
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
    } finally {
      setPending(null);
    }
  }

  const input = "bg-void border border-line px-2 py-1 text-xs text-slate-200 font-mono focus:border-amber focus:outline-none";

  return (
    <Panel
      title="Control"
      right={<span className={`text-[10px] px-2 py-0.5 rounded-full border ${locked ? "border-amber-500 text-amber-400" : "border-emerald-500 text-emerald-400"}`}>{locked ? "LOCKED" : "armed"}</span>}
    >
      <div className="flex flex-wrap items-center gap-2">
        <select value={domain} onChange={(e) => setDomain(e.target.value as Domain)} className={input}>
          <option value="red">red</option>
          <option value="blue">blue</option>
          <option value="purple">purple</option>
        </select>
        <input className={input} placeholder={domain === "blue" ? "target (optional)" : "target IP"} value={target} onChange={(e) => setTarget(e.target.value)} />
        <input className={`${input} flex-1 min-w-[140px]`} placeholder="task (optional)" value={task} onChange={(e) => setTask(e.target.value)} />
        <select value={brainTier} onChange={(e) => setBrainTier(e.target.value)} className={input}>
          <option value="local">local</option>
          <option value="expensive">expensive</option>
        </select>
        {domain !== "blue" && (
          <label className="text-xs text-slate-400 flex items-center gap-1">
            <input type="checkbox" checked={stealth} onChange={(e) => setStealth(e.target.checked)} /> stealth
          </label>
        )}
        <button onClick={run} disabled={pending !== null || locked} className="font-display uppercase tracking-widest bg-amber/15 border border-amber text-amber glow text-xs px-4 py-1 disabled:opacity-40 hover:bg-amber/25">
          {pending === "run" ? "···" : "▶ Run"}
        </button>
        {locked ? (
          <button onClick={() => toggleLock(false)} disabled={pending !== null} className="font-display uppercase tracking-widest border border-phos text-phos text-xs px-3 py-1 hover:bg-phos/10">Unlock</button>
        ) : (
          <button onClick={() => toggleLock(true)} disabled={pending !== null} className="font-display uppercase tracking-widest border border-redteam text-redteam text-xs px-3 py-1 hover:bg-redteam/10">⏻ Lock</button>
        )}
      </div>
      {msg && <div className={`mt-2 text-xs ${msg.ok ? "text-emerald-400" : "text-rose-400"}`}>{msg.text}</div>}
    </Panel>
  );
}
