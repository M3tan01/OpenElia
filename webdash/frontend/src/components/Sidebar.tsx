import { useState } from "react";

type NavView = { id: string; label: string; disabled?: boolean };
type NavGroup = { group: string; views: NavView[] };

const NAV: NavGroup[] = [
  {
    group: "Operations",
    views: [
      { id: "c2", label: "C2 Console" },
      { id: "agents", label: "Agent Activity" },
      { id: "graph", label: "Attack Graph" },
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
      { id: "roe", label: "RoE / Scope", disabled: true },
    ],
  },
];

export function Sidebar({ activeView, onSelect }: {
  activeView: string;
  onSelect: (id: string) => void;
}) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const toggle = (g: string) => setCollapsed((c) => ({ ...c, [g]: !c[g] }));

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
                  {views.map(({ id, label, disabled }) => {
                    const active = id === activeView;
                    return (
                      <button
                        key={id}
                        type="button"
                        disabled={disabled}
                        onClick={() => !disabled && onSelect(id)}
                        aria-current={active ? "page" : undefined}
                        className={`w-full text-left pl-4 pr-2 py-1.5 text-sm font-mono border-l-2 transition-colors ${
                          active
                            ? "border-amber text-amber"
                            : disabled
                            ? "border-transparent text-dim/40 cursor-not-allowed"
                            : "border-transparent text-dim hover:text-amber/80"
                        }`}
                      >
                        {label}
                        {disabled && (
                          <span aria-hidden="true" className="ml-2 text-[9px] uppercase tracking-wider text-dim/40">soon</span>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>
    </aside>
  );
}
