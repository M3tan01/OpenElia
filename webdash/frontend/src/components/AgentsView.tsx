import { useState } from "react";
import { AgentInfo, ReportBriefResp, RunResp, apiPost } from "../api";
import { useAgentsRoster } from "../useAgentsRoster";
import { agentDisplayName } from "../agentNames";
import { Badge, Panel } from "./Panel";

// ── mode directives ──────────────────────────────────────────────────────────

const MODE_DIRECTIVES = {
  passive:
    "Operate passively: reconnaissance/observation only; no active exploitation.",
  active:
    "Operate actively: full engagement permitted within RoE.",
  stealth:
    "Operate in stealth: slow timing, jitter, living-off-the-land; avoid noisy scans.",
} as const;

type Mode = keyof typeof MODE_DIRECTIVES;

// ── domain ordering ──────────────────────────────────────────────────────────

const DOMAIN_ORDER = ["red", "blue", "reporter"];

function domainLabel(domain: string): string {
  switch (domain) {
    case "red":      return "RED TEAM";
    case "blue":     return "BLUE TEAM";
    case "reporter": return "REPORTER";
    default:         return domain.toUpperCase();
  }
}

function domainColor(domain: string): string {
  switch (domain) {
    case "red":      return "text-redteam";
    case "blue":     return "text-blueteam";
    case "reporter": return "text-amber";
    default:         return "text-dim";
  }
}

// ── per-card component ───────────────────────────────────────────────────────

function AgentCard({ agent }: { agent: AgentInfo }) {
  const [instruction, setInstruction] = useState("");
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<Mode>("passive");
  const [brainTier, setBrainTier] = useState<"local" | "expensive">("local");
  const [running, setRunning] = useState(false);
  const [run, setRun] = useState<RunResp | null>(null);
  const [brief, setBrief] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const isReporter = agent.domain === "reporter";
  const isRed = agent.domain === "red";

  // stealth only available for red agents that support it
  const availableModes: Mode[] = isRed && agent.supports_stealth
    ? ["passive", "active", "stealth"]
    : ["passive", "active"];

  // enforce mode reset if stealth not available
  const effectiveMode: Mode =
    mode === "stealth" && !availableModes.includes("stealth") ? "passive" : mode;

  const task =
    instruction.trim()
      ? `${MODE_DIRECTIVES[effectiveMode]}\n\n${instruction.trim()}`
      : MODE_DIRECTIVES[effectiveMode];

  const runDisabled =
    running ||
    (isRed && !target.trim());

  async function handleRun() {
    if (runDisabled) return;
    setRunning(true);
    setErr(null);
    setRun(null);
    setBrief(null);
    try {
      if (isReporter) {
        // Reporter has no /run endpoint — it summarizes current findings.
        const r = await apiPost<ReportBriefResp>("/api/report/brief", {
          brain_tier: brainTier,
          confirm: true,
        });
        setBrief(r.markdown);
        return;
      }
      let r: RunResp;
      if (isRed) {
        r = await apiPost<RunResp>("/api/run/red", {
          target: target.trim(),
          task,
          stealth: effectiveMode === "stealth",
          brain_tier: brainTier,
          agent: agent.name,
          confirm: true,
        });
      } else {
        r = await apiPost<RunResp>("/api/run/blue", {
          task,
          target: target.trim() || null,
          brain_tier: brainTier,
          agent: agent.name,
          confirm: true,
        });
      }
      setRun(r);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }

  const input =
    "bg-void border border-line px-2 py-1 text-xs text-slate-200 font-mono focus:border-amber focus:outline-none";
  const btn =
    "font-display uppercase tracking-widest bg-amber/15 border border-amber text-amber glow text-xs px-3 py-1 hover:bg-amber/25 disabled:opacity-40 shrink-0";

  return (
    <div className="border border-line bg-surface/40 p-3 flex flex-col gap-2">
      {/* agent name + description */}
      <div>
        <div className="font-mono text-[12px] text-amber glow font-semibold">
          {agentDisplayName(agent.name)}
        </div>
        <div className="font-mono text-[11px] text-dim mt-0.5 leading-relaxed">
          {agent.description}
        </div>
      </div>

      {/* reporter summarizes current findings — instruction/target/mode N/A */}
      {!isReporter && (
        <>
          {/* instruction */}
          <textarea
            value={instruction}
            onChange={(e) => setInstruction(e.target.value)}
            aria-label={`instruction for ${agent.name}`}
            placeholder="what should this agent do?"
            rows={3}
            className={`${input} resize-y w-full`}
          />

          {/* target */}
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={isRed ? "target host / CIDR (required)" : "target host / CIDR (optional)"}
            aria-label={`target for ${agent.name}`}
            className={`${input} w-full`}
          />

          {/* mode control */}
          <div className="space-y-1">
            <div className="flex gap-2 items-center flex-wrap">
              {availableModes.map((m) => (
                <label key={m} className="flex items-center gap-1 cursor-pointer select-none">
                  <input
                    type="radio"
                    name={`mode-${agent.name}`}
                    value={m}
                    checked={effectiveMode === m}
                    onChange={() => setMode(m)}
                    className="accent-amber"
                  />
                  <span className="font-mono text-[11px] text-slate-300 capitalize">{m}</span>
                </label>
              ))}
            </div>
            {/* inline mode example */}
            <div className="font-mono text-[10px] text-dim/80 italic border-l-2 border-amber/30 pl-2 leading-relaxed">
              {MODE_DIRECTIVES[effectiveMode]}
            </div>
          </div>
        </>
      )}

      {/* brain tier + run */}
      <div className="flex items-center gap-2 flex-wrap">
        <select
          value={brainTier}
          onChange={(e) => setBrainTier(e.target.value as "local" | "expensive")}
          aria-label={`brain tier for ${agent.name}`}
          className={`${input} shrink-0`}
        >
          <option value="local">local</option>
          <option value="expensive">expensive</option>
        </select>

        <button
          type="button"
          onClick={handleRun}
          disabled={runDisabled}
          title={
            isReporter
              ? "summarize current findings into a brief"
              : isRed && !target.trim()
              ? "target required for red agents"
              : undefined
          }
          className={btn}
        >
          {running ? "···" : isReporter ? "▶ Generate brief" : "▶ Run"}
        </button>

        {isReporter && !brief && (
          <span className="font-mono text-[10px] text-dim italic">
            summarizes all current findings
          </span>
        )}

        {run && (
          <span className="font-mono text-[11px] text-phos">
            launched: {run.run_id}
          </span>
        )}

        {err && <Badge ok={false}>{err}</Badge>}
      </div>

      {brief && (
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-dim uppercase tracking-widest">
              brief
            </span>
            <button
              type="button"
              onClick={() => setBrief(null)}
              className="font-mono text-[10px] text-dim hover:text-amber"
            >
              dismiss
            </button>
          </div>
          <pre className="whitespace-pre-wrap font-mono text-[11px] text-slate-200 bg-void border border-line p-2 max-h-72 overflow-auto leading-relaxed">
            {brief}
          </pre>
        </div>
      )}
    </div>
  );
}

// ── main view ────────────────────────────────────────────────────────────────

export function AgentsView() {
  const { data: agentsData, error: err, loading } = useAgentsRoster();
  const agents: AgentInfo[] = agentsData?.agents ?? [];
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  // which agent is selected within each domain (by agent.name)
  const [selected, setSelected] = useState<Record<string, string>>({});

  const toggle = (domain: string) =>
    setCollapsed((c) => ({ ...c, [domain]: !c[domain] }));

  // group agents by domain in order: red → blue → reporter → others
  const grouped = DOMAIN_ORDER.reduce<Record<string, AgentInfo[]>>(
    (acc, d) => ({ ...acc, [d]: [] }),
    {}
  );
  for (const a of agents) {
    if (!grouped[a.domain]) grouped[a.domain] = [];
    grouped[a.domain].push(a);
  }
  // collect any domains not in DOMAIN_ORDER at the end
  const domainKeys = [
    ...DOMAIN_ORDER,
    ...Object.keys(grouped).filter((d) => !DOMAIN_ORDER.includes(d)),
  ];

  return (
    <Panel title="Agents" className="h-full">
      {loading && (
        <div className="font-mono text-xs text-dim italic">loading agents…</div>
      )}
      {err && <Badge ok={false}>{err}</Badge>}

      {!loading && !err && agents.length === 0 && (
        <div className="font-mono text-xs text-dim italic">no agents registered</div>
      )}

      <div className="space-y-5">
        {domainKeys.map((domain) => {
          const list = grouped[domain] ?? [];
          if (list.length === 0) return null;
          const isCollapsed = collapsed[domain] ?? false;
          // default selection = first agent in the domain
          const selectedName =
            selected[domain] && list.some((a) => a.name === selected[domain])
              ? selected[domain]
              : list[0].name;
          const selectedAgent =
            list.find((a) => a.name === selectedName) ?? list[0];
          return (
            <section key={domain}>
              {/* domain header — click to collapse/expand */}
              <button
                type="button"
                onClick={() => toggle(domain)}
                aria-expanded={!isCollapsed}
                aria-controls={`agents-${domain}`}
                className={`w-full flex items-center gap-1.5 font-display text-[10px] font-semibold uppercase tracking-[0.25em] mb-2 pb-1 border-b border-line cursor-pointer select-none hover:opacity-80 ${domainColor(domain)}`}
              >
                <span
                  className={`inline-block transition-transform duration-150 ${isCollapsed ? "" : "rotate-90"}`}
                  aria-hidden="true"
                >
                  ▸
                </span>
                {domainLabel(domain)}
                <span className="ml-auto opacity-60 normal-case tracking-normal">
                  {list.length}
                </span>
              </button>
              {!isCollapsed && (
                <div id={`agents-${domain}`} className="space-y-2">
                  {/* agent picker — choose one instead of scrolling the stack */}
                  <label className="flex items-center gap-2">
                    <span className="font-display text-[10px] uppercase tracking-[0.15em] text-dim shrink-0">
                      Agent
                    </span>
                    <select
                      value={selectedName}
                      onChange={(e) =>
                        setSelected((s) => ({ ...s, [domain]: e.target.value }))
                      }
                      aria-label={`select ${domainLabel(domain)} agent`}
                      className="bg-void border border-line px-2 py-1 text-xs text-slate-200 font-mono focus:border-amber focus:outline-none w-full"
                    >
                      {list.map((a) => (
                        <option key={a.name} value={a.name}>
                          {agentDisplayName(a.name)}
                        </option>
                      ))}
                    </select>
                  </label>
                  {/* only the chosen agent's card renders; key forces fresh
                      form state when switching agents */}
                  <AgentCard key={selectedAgent.name} agent={selectedAgent} />
                </div>
              )}
            </section>
          );
        })}
      </div>
    </Panel>
  );
}
