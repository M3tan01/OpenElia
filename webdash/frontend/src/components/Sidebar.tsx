const VIEWS = [
  { id: "c2", label: "C2 Console" },
];

export function Sidebar({ activeView, onSelect }: {
  activeView: string;
  onSelect: (id: string) => void;
}) {

  return (
    <aside className="bg-surface/80 border-r border-line h-full w-52 flex flex-col backdrop-blur-[1px]">
      <div className="px-3 py-2 border-b border-line">
        <h3 className="font-display text-[11px] font-semibold uppercase tracking-[0.22em] text-amber glow">
          <span className="text-amber/60">▸</span>
          VIEWS
        </h3>
      </div>

      <nav className="flex-1 p-3 space-y-1 overflow-auto scroll-thin" aria-label="Views">
        {VIEWS.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            onClick={() => onSelect(id)}
            aria-current={id === activeView ? "page" : undefined}
            className={`w-full text-left px-3 py-2 text-sm font-mono transition-colors ${
              id === activeView
                ? "border-l-2 border-amber text-amber"
                : "text-dim border-l-2 border-transparent hover:text-amber/80"
            }`}
          >
            {label}
          </button>
        ))}
      </nav>
    </aside>
  );
}
