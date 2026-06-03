import { useState } from "react";
import { apiPost } from "../api";
import { Badge } from "./Panel";

export function CustomAdversaryForm({ onCreated }: { onCreated?: (stem: string) => void }) {
  const [name, setName] = useState("");
  const [alias, setAlias] = useState("");
  const [description, setDescription] = useState("");
  const [ttps, setTtps] = useState("");
  const [tools, setTools] = useState("");
  const [stealth, setStealth] = useState(false);
  const [rationale, setRationale] = useState("");
  const [pending, setPending] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  async function save() {
    if (pending) return;
    if (!name.trim()) { setErr("name is required"); return; }
    setPending(true); setErr(null); setSaved(null);
    try {
      const r = await apiPost<{ stem: string; saved: string }>("/api/adversaries", {
        name: name.trim(),
        alias: alias.trim(),
        description: description.trim(),
        preferred_ttps: ttps.split(",").map((t) => t.trim()).filter(Boolean),
        tools: tools.split(",").map((t) => t.trim()).filter(Boolean),
        stealth_required: stealth,
        rationale: rationale.trim(),
        confirm: true,
      });
      setSaved(r.saved);
      onCreated?.(r.stem);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setPending(false); }
  }

  const label = "font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-1 block";
  const field = "w-full bg-void border border-line px-2 py-1 text-xs font-mono text-slate-200 focus:border-amber focus:outline-none";

  return (
    <div className="space-y-2">
      <label className={label}>Name</label>
      <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Custom-APT" className={field} />

      <label className={label}>Alias</label>
      <input value={alias} onChange={(e) => setAlias(e.target.value)} placeholder="short alias" className={field} />

      <label className={label}>Description</label>
      <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="who they are" className={field} />

      <label className={label}>Preferred TTPs</label>
      <input value={ttps} onChange={(e) => setTtps(e.target.value)} placeholder="comma-separated (T1059, T1003)" className={field} />

      <label className={label}>Tools</label>
      <input value={tools} onChange={(e) => setTools(e.target.value)} placeholder="comma-separated (mimikatz, cobaltstrike)" className={field} />

      <label className="flex items-center gap-2 text-xs font-mono text-dim">
        <input type="checkbox" checked={stealth} onChange={(e) => setStealth(e.target.checked)} /> stealth required
      </label>

      <label className={label}>Rationale</label>
      <input value={rationale} onChange={(e) => setRationale(e.target.value)} placeholder="why this profile" className={field} />

      {err && <Badge ok={false}>{err}</Badge>}
      {saved && <div className="text-[11px] font-mono text-phos">saved: {saved}</div>}

      <button type="button" onClick={save} disabled={pending}
        className="font-display uppercase tracking-widest bg-amber/15 border border-amber text-amber glow text-xs px-4 py-1 disabled:opacity-40 hover:bg-amber/25">
        {pending ? "···" : "▶ Save Custom Adversary"}
      </button>
    </div>
  );
}
