import { useEffect, useState } from "react";
import { apiGet, SystemResp } from "../api";

type NavView = { id: string; label: string };
type NavGroup = { group: string; views: NavView[] };

const NAV: NavGroup[] = [
  {
    group: "Operations",
    views: [
      { id: "c2", label: "C2 Console" },
      { id: "engagements", label: "Sessions" },
      { id: "playbooks", label: "Playbooks" },
      { id: "agents", label: "Agent Activity" },
      { id: "graph", label: "Attack Graph" },
      { id: "apt", label: "APT Profiles" },
      { id: "forge", label: "Adversary Forge" },
    ],
  },
  {
    group: "Intelligence",
    views: [
      { id: "audit", label: "Audit Timeline" },
      { id: "cost", label: "Cost & MITRE" },
    ],
  },
  {
    group: "Config",
    views: [
      { id: "models", label: "Brain Models" },
      { id: "roe", label: "RoE / Scope" },
    ],
  },
];

export function Sidebar({ activeView, onSelect }: {
  activeView: string;
  onSelect: (id: string) => void;
}) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const toggle = (g: string) => setCollapsed((c) => ({ ...c, [g]: !c[g] }));

  const [system, setSystem] = useState<SystemResp | null>(null);
  useEffect(() => {
    apiGet<SystemResp>("/api/system").then(setSystem).catch(() => setSystem(null));
    const id = setInterval(
      () => apiGet<SystemResp>("/api/system").then(setSystem).catch(() => setSystem(null)),
      10_000,
    );
    return () => clearInterval(id);
  }, []);

  return (
    <aside className="bg-surface/80 border-r border-line h-full w-52 flex flex-col backdrop-blur-[1px]">
      <div className="px-3 py-2 border-b border-line">
        <h3 className="font-display text-[11px] font-semibold uppercase tracking-[0.22em] text-amber glow">
          <span className="text-amber/60">▸</span>
          VIEWS
        </h3>
      </div>

      <nav className="flex-1 p-2 overflow-auto scroll-thin" aria-label="Views">
        {NAV.map(({ group, views }) => {
          const open = !collapsed[group];
          return (
            <div key={group} className="mb-2">
              <button
                type="button"
                onClick={() => toggle(group)}
                aria-expanded={open}
                aria-controls={`navgroup-${group}`}
                className="w-full flex items-center justify-between px-2 py-1.5 font-display text-[10px] font-semibold uppercase tracking-[0.2em] text-dim hover:text-amber/80 transition-colors"
              >
                <span>{group}</span>
                <span aria-hidden="true" className={`text-amber/50 transition-transform ${open ? "" : "-rotate-90"}`}>▾</span>
              </button>

              {open && (
                <div id={`navgroup-${group}`} className="space-y-0.5 mt-0.5">
                  {views.map(({ id, label }) => {
                    const active = id === activeView;
                    return (
                      <button
                        key={id}
                        type="button"
                        onClick={() => onSelect(id)}
                        aria-current={active ? "page" : undefined}
                        className={`w-full text-left pl-4 pr-2 py-1.5 text-sm font-mono border-l-2 transition-colors ${
                          active
                            ? "border-amber text-amber"
                            : "border-transparent text-dim hover:text-amber/80"
                        }`}
                      >
                        {label}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      <div className="px-3 py-2 border-t border-line">
        <h3 className="font-display text-[11px] font-semibold uppercase tracking-[0.22em] text-dim mb-1.5">
          SYSTEM
        </h3>
        <div className="font-mono text-[11px] space-y-1">
          <div className="flex items-center gap-1.5">
            <span className="text-dim">GATEWAY:</span>
            <span className={system?.gateway === "running" ? "text-phos glow" : "text-dim"}>
              {system ? system.gateway.toUpperCase() : "—"}
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-dim">ACTIVE:</span>
            <span className="text-amber">
              {system ? system.active_engagements : "—"}
            </span>
          </div>
        </div>
      </div>
    </aside>
  );
}
