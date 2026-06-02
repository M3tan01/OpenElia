import { ReactNode } from "react";

export function Panel({ title, right, children, className = "" }: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`hud bg-surface/80 border border-line flex flex-col min-h-0 h-full backdrop-blur-[1px] ${className}`}
    >
      <header className="flex items-center justify-between px-3 py-2 border-b border-line">
        <h2 className="font-display text-[11px] font-semibold uppercase tracking-[0.22em] text-amber glow flex items-center gap-2">
          <span className="text-amber/60">▸</span>
          {title}
        </h2>
        <div className="flex items-center gap-2">{right}</div>
      </header>
      <div className="p-3 overflow-auto scroll-thin flex-1 min-h-0">{children}</div>
    </section>
  );
}

export function Badge({ ok, children }: { ok: boolean; children: ReactNode }) {
  return (
    <span
      className={`font-mono text-[10px] px-2 py-0.5 border uppercase tracking-wider ${
        ok ? "border-phos/50 text-phos" : "border-redteam/60 text-redteam glow"
      }`}
    >
      {children}
    </span>
  );
}
