import { useEffect, useState } from "react";
import { apiGet, apiPost, AdversaryResp, RoEResp, RunResp, StateResp } from "../api";
import { Badge, Panel } from "./Panel";

type Domain = "red" | "purple" | "blue";

const input =
  "bg-void border border-line px-2 py-1 text-xs text-slate-200 font-mono focus:border-amber focus:outline-none w-full";

function TtpChip({ label }: { label: string }) {
  return (
    <span className="font-mono text-[10px] px-1.5 py-0.5 border border-amber/30 text-amber/70 bg-amber/5">
      {label}
    </span>
  );
}

function ApplyPanel({
  profile,
  defaultTarget,
  onClose,
}: {
  profile: AdversaryResp;
  defaultTarget: string;
  onClose: () => void;
}) {
  const [domain, setDomain] = useState<Domain>("red");
  const [target, setTarget] = useState(defaultTarget);
  const [pending, setPending] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // red/purple launch offensive ops — a blank target would skip the server
  // scope check, so require one here. blue may run target-less ("unknown").
  const targetRequired = domain !== "blue";
  const canApply = !pending && (!targetRequired || target.trim() !== "");

  async function apply() {
    if (!canApply) return;
    setPending(true);
    setMsg(null);
    try {
      const body: Record<string, unknown> = {
        target,
        apt_profile: profile.name,
        task: `APT emulation: ${profile.name}`,
        confirm: true,
      };
      if (domain !== "blue") {
        body.stealth = profile.stealth_required;
      }
      const r = await apiPost<RunResp>(`/api/run/${domain}`, body);
      setMsg({ ok: true, text: `run ${r.run_id} ${r.status}` });
    } catch (e: unknown) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="mt-3 border border-amber/40 bg-surface/60 p-3 space-y-2">
      <div className="font-display text-[10px] uppercase tracking-[0.2em] text-amber/70 mb-1">
        Apply — {profile.alias}
      </div>
      <div className="flex flex-wrap gap-2 items-center">
        <select
          value={domain}
          onChange={(e) => setDomain(e.target.value as Domain)}
          className="bg-void border border-line px-2 py-1 text-xs text-slate-200 font-mono focus:border-amber focus:outline-none"
        >
          <option value="red">red</option>
          <option value="purple">purple</option>
          <option value="blue">blue</option>
        </select>
        <div className="flex-1 min-w-[160px]">
          <input
            className={input}
            placeholder="target IP / hostname"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </div>
      </div>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={apply}
          disabled={!canApply}
          title={targetRequired && target.trim() === "" ? "target required for red/purple" : undefined}
          className="font-display uppercase tracking-widest bg-amber/15 border border-amber text-amber glow text-xs px-4 py-1 disabled:opacity-40 hover:bg-amber/25"
        >
          {pending ? "···" : "▶ Confirm Apply"}
        </button>
        <button
          type="button"
          onClick={onClose}
          className="font-display uppercase tracking-widest border border-line text-dim text-xs px-3 py-1 hover:border-amber/40 hover:text-amber/70"
        >
          Cancel
        </button>
      </div>
      {msg && (
        <div className={`text-xs font-mono ${msg.ok ? "text-phos" : "text-redteam glow"}`}>
          {msg.text}
        </div>
      )}
    </div>
  );
}

function ProfileCard({
  profile,
  prohibited,
  defaultTarget,
}: {
  profile: AdversaryResp;
  prohibited: Set<string>;
  defaultTarget: string;
}) {
  const [applying, setApplying] = useState(false);
  const conflicts = profile.tools.filter((t) => prohibited.has(t));

  return (
    <div className="border border-line bg-surface/50 p-3 space-y-2">
      {/* header row */}
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <span className="font-display text-sm font-semibold text-amber glow">
            {profile.alias}
          </span>
          {profile.alias !== profile.name && (
            <span className="font-mono text-[11px] text-dim ml-2">({profile.name})</span>
          )}
        </div>
        <div className="flex flex-wrap gap-1">
          {profile.stealth_required && (
            <span className="font-mono text-[10px] px-2 py-0.5 border border-redteam/60 text-redteam uppercase tracking-wider">
              stealth
            </span>
          )}
          {conflicts.length > 0 && (
            <span className="font-mono text-[10px] px-2 py-0.5 border border-amber/60 text-amber uppercase tracking-wider glow">
              RoE CONFLICT: {conflicts.join(", ")}
            </span>
          )}
        </div>
      </div>

      {/* description */}
      {profile.description && (
        <p className="text-xs text-slate-300 leading-relaxed">{profile.description}</p>
      )}

      {/* TTPs */}
      {profile.preferred_ttps.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {profile.preferred_ttps.map((t) => (
            <TtpChip key={t} label={t} />
          ))}
        </div>
      )}

      {/* tools */}
      {profile.tools.length > 0 && (
        <div>
          <span className="font-display text-[10px] uppercase tracking-[0.18em] text-amber/60 mr-1">
            tools:
          </span>
          <span className="font-mono text-xs text-slate-400">{profile.tools.join(", ")}</span>
        </div>
      )}

      {/* rationale */}
      {profile.rationale && (
        <p className="text-[11px] text-dim italic">{profile.rationale}</p>
      )}

      {/* apply toggle */}
      {!applying && (
        <button
          type="button"
          onClick={() => setApplying(true)}
          className="font-display uppercase tracking-widest border border-redteam/60 text-redteam text-xs px-3 py-1 hover:bg-redteam/10 mt-1"
        >
          Apply
        </button>
      )}

      {applying && (
        <ApplyPanel
          profile={profile}
          defaultTarget={defaultTarget}
          onClose={() => setApplying(false)}
        />
      )}
    </div>
  );
}

export function APTProfilesView() {
  const [profiles, setProfiles] = useState<AdversaryResp[] | null>(null);
  const [roe, setRoe] = useState<RoEResp | null>(null);
  const [defaultTarget, setDefaultTarget] = useState("");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      apiGet<AdversaryResp[]>("/api/adversaries"),
      apiGet<RoEResp>("/api/roe"),
      apiGet<StateResp>("/api/state"),
    ])
      .then(([p, r, s]) => {
        setProfiles(p);
        setRoe(r);
        setDefaultTarget(s.engagement?.target ?? "");
      })
      .catch((e: unknown) => {
        setErr(e instanceof Error ? e.message : String(e));
      });
  }, []);

  const prohibited = new Set(roe?.prohibited_tools ?? []);

  const readOnlyBadge = (
    <span className="font-mono text-[10px] px-2 py-0.5 border border-amber/40 text-amber/60 uppercase tracking-wider">
      {profiles ? `${profiles.length} profiles` : "loading"}
    </span>
  );

  return (
    <Panel title="APT Profiles" right={readOnlyBadge} className="h-full">
      {err && (
        <div className="mb-3">
          <Badge ok={false}>{err}</Badge>
        </div>
      )}
      {!profiles && !err && (
        <div className="text-dim text-xs italic">loading…</div>
      )}
      {profiles && profiles.length === 0 && (
        <div className="text-dim text-xs italic">no adversary profiles loaded</div>
      )}
      {profiles && profiles.length > 0 && (
        <div className="space-y-3">
          {profiles.map((p) => (
            <ProfileCard
              key={p.name}
              profile={p}
              prohibited={prohibited}
              defaultTarget={defaultTarget}
            />
          ))}
        </div>
      )}
    </Panel>
  );
}
