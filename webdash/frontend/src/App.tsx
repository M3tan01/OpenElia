import { useCallback, useEffect, useState } from "react";
import { apiGet, StateResp, TOKEN, useStream } from "./api";
import { C2ConsoleView } from "./components/C2ConsoleView";

export default function App() {
  const stream = useStream();
  const [state, setState] = useState<StateResp | null>(null);

  const refresh = useCallback(() => {
    apiGet<StateResp>("/api/state").then(setState).catch(() => {});
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
  }, [refresh]);

  const snapshot = state ?? stream.snapshot;
  const eng = snapshot?.engagement;

  if (!TOKEN) {
    return (
      <div className="h-screen flex items-center justify-center px-6">
        <div className="hud border border-redteam/50 bg-surface px-6 py-5 max-w-lg">
          <div className="font-display text-redteam glow uppercase tracking-[0.2em] text-sm mb-2">
            ⚠ no auth token
          </div>
          <p className="text-dim text-xs leading-relaxed">
            Open the URL printed by{" "}
            <code className="text-amber">python main.py dashboard --web</code> — it carries
            the <code className="text-amber">#token=…</code> fragment required for C2 access.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col text-[13px]">
      <header className="flex items-center justify-between px-4 py-2 border-b border-line bg-surface/90 animate-flicker">
        <div className="flex items-baseline gap-3">
          <span className="font-display font-700 text-amber glow tracking-[0.3em] text-lg">
            OPENELIA
          </span>
          <span className="font-display text-dim tracking-[0.4em] text-[10px]">// C2 CONSOLE</span>
          <span className="font-mono text-[11px] text-dim ml-2">
            {eng ? (
              <>
                <span className="text-blueteam">{eng.id}</span>
                <span className="text-dim"> ▪ TGT </span>
                <span className="text-redteam">{eng.target}</span>
              </>
            ) : (
              "— no active engagement —"
            )}
          </span>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest">
          <span
            className={`inline-block w-2 h-2 rounded-full ${
              stream.connected ? "bg-phos glow animate-blink" : "bg-dim"
            }`}
          />
          <span className={stream.connected ? "text-phos" : "text-dim"}>
            {stream.connected ? "telemetry live" : "offline"}
          </span>
        </div>
      </header>

      <C2ConsoleView snapshot={snapshot} stream={stream} refresh={refresh} />
    </div>
  );
}
