import { useState } from "react";
import { apiPost } from "../api";
import { Badge } from "./Panel";

type Domain = "red" | "blue" | "purple";
type PhaseDraft = { name: string; tools: string; post_analysis: string };

export function PlaybookCreateForm({ onCreated, onCancel }: {
  onCreated: () => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [domain, setDomain] = useState<Domain>("red");
  const [passive, setPassive] = useState(false);
  const [stealth, setStealth] = useState(false);
  const [targetRequired, setTargetRequired] = useState(true);
  const [phases, setPhases] = useState<PhaseDraft[]>([{ name: "", tools: "", post_analysis: "" }]);
  const [pending, setPending] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const setPhase = (i: number, patch: Partial<PhaseDraft>) =>
    setPhases((ps) => ps.map((p, j) => (j === i ? { ...p, ...patch } : p)));
  const addPhase = () => setPhases((ps) => [...ps, { name: "", tools: "", post_analysis: "" }]);
  const removePhase = (i: number) => setPhases((ps) => ps.filter((_, j) => j !== i));

  async function save() {
    if (pending) return;
    if (!/^[a-z0-9][a-z0-9_-]*$/.test(name)) {
      setErr("name must be lowercase alphanumeric with _ or - (no spaces or slashes)");
      return;
    }
    const cleanPhases = phases
      .filter((p) => p.name.trim())
      .map((p) => ({
        name: p.name.trim(),
        tools: p.tools.split(",").map((t) => t.trim()).filter(Boolean),
        post_analysis: p.post_analysis.trim() || null,
      }));
    if (cleanPhases.length === 0) {
      setErr("add at least one phase with a name");
      return;
    }
    setPending(true); setErr(null);
    try {
      await apiPost("/api/playbooks", {
        name,
        description,
        domain,
        passive,
        stealth,
        variables: targetRequired
          ? { target: { required: true, description: "Target host or CIDR" } }
          : {},
        phases: cleanPhases,
        confirm: true,
      });
      onCreated();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setPending(false); }
  }

  const label = "font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-1 block";
  const field = "w-full bg-void border border-line px-2 py-1 text-xs font-mono text-slate-200 focus:border-amber focus:outline-none";

  return (
    <div className="border border-line bg-surface/50 p-3 overflow-auto scroll-thin flex flex-col">
      <div className="flex items-center justify-between mb-2">
        <div className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70">New Playbook</div>
        <button type="button" onClick={onCancel} className="font-mono text-[11px] text-dim hover:text-amber">✕ cancel</button>
      </div>

      <label className={label}>Name</label>
      <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. recon-quick" className={`${field} mb-2`} />

      <label className={label}>Description</label>
      <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="short summary — supports {target}" className={`${field} mb-2`} />

      <label className={label}>Domain</label>
      <div className="flex gap-2 mb-2">
        {(["red", "blue", "purple"] as Domain[]).map((d) => (
          <button key={d} type="button" onClick={() => setDomain(d)}
            className={`font-display uppercase tracking-widest text-xs px-3 py-1 border ${domain === d ? "border-amber text-amber glow" : "border-line text-dim"}`}>
            {d}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap gap-4 mb-3 text-xs font-mono text-dim">
        <label className="flex items-center gap-2"><input type="checkbox" checked={passive} onChange={(e) => setPassive(e.target.checked)} /> passive</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={stealth} onChange={(e) => setStealth(e.target.checked)} /> stealth</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={targetRequired} onChange={(e) => setTargetRequired(e.target.checked)} /> require target</label>
      </div>

      <div className="flex items-center justify-between mb-1">
        <label className={label.replace(" mb-1 block", "")}>Phases</label>
        <button type="button" onClick={addPhase} className="font-mono text-[11px] text-amber hover:glow">＋ add phase</button>
      </div>
      <div className="space-y-2 mb-3">
        {phases.map((p, i) => (
          <div key={i} className="border-l-2 border-phos/50 pl-2 space-y-1">
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11px] text-phos">{i + 1}.</span>
              <input value={p.name} onChange={(e) => setPhase(i, { name: e.target.value })} placeholder="phase name (e.g. recon)" className={field} />
              {phases.length > 1 && (
                <button type="button" onClick={() => removePhase(i)} className="font-mono text-[11px] text-dim hover:text-rose-400">✕</button>
              )}
            </div>
            <input value={p.tools} onChange={(e) => setPhase(i, { tools: e.target.value })} placeholder="tools, comma-separated (nmap, gobuster)" className={field} />
            <input value={p.post_analysis} onChange={(e) => setPhase(i, { post_analysis: e.target.value })} placeholder="directive — supports {target}" className={field} />
          </div>
        ))}
      </div>

      {err && <div className="mb-2"><Badge ok={false}>{err}</Badge></div>}

      <button type="button" onClick={save} disabled={pending}
        className="font-display uppercase tracking-widest bg-amber/15 border border-amber text-amber glow text-xs px-4 py-1 disabled:opacity-40 hover:bg-amber/25 self-end">
        {pending ? "···" : "▶ Save Playbook"}
      </button>
    </div>
  );
}
