import { useEffect, useState } from "react";
import { apiGet, apiPost, ModelsResp } from "../api";
import { Panel } from "./Panel";

const PROVIDERS = ["openai", "anthropic", "google"];

export function ModelSelector() {
  const [data, setData] = useState<ModelsResp | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const [localModel, setLocalModel] = useState("");
  const [cloudProvider, setCloudProvider] = useState("openai");
  const [cloudModel, setCloudModel] = useState("");
  const [hybridAgent, setHybridAgent] = useState("");
  const [authProvider, setAuthProvider] = useState("openai");
  const [authKey, setAuthKey] = useState("");

  const load = () => apiGet<ModelsResp>("/api/models").then(setData).catch(() => {});
  useEffect(() => { load(); }, []);

  async function call(path: string, body: Record<string, unknown>, ok: string) {
    setMsg(null);
    try {
      await apiPost(path, { ...body, confirm: true });
      setMsg({ ok: true, text: ok });
      setAuthKey("");
      load();
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
    }
  }

  const cfg = (data?.config ?? {}) as Record<string, any>;
  const agents = data ? Object.values(data.agents).flat() : [];
  const input = "bg-void border border-line px-2 py-1 text-xs text-slate-200 font-mono focus:border-amber focus:outline-none";
  const btn = "font-display uppercase tracking-wider bg-amber/15 border border-amber text-amber text-[11px] px-2 py-1 hover:bg-amber/25 disabled:opacity-40";

  return (
    <Panel title="Brain Models" right={<span className="text-[10px] text-slate-500">mode: {cfg.mode ?? "?"}</span>}>
      <div className="space-y-3 text-xs">
        <div className="text-slate-500">
          local: <span className="text-slate-300">{cfg.local_model}</span> · cloud:{" "}
          <span className="text-slate-300">{cfg.cloud_provider}/{cfg.cloud_model}</span>
        </div>

        <div className="flex gap-2 items-center">
          <input className={`${input} flex-1`} placeholder={`local model (${cfg.local_model ?? "ollama"})`} value={localModel} onChange={(e) => setLocalModel(e.target.value)} />
          <button className={btn} disabled={!localModel} onClick={() => call("/api/models/local", { model: localModel }, "local model set")}>Set local</button>
        </div>

        <div className="flex gap-2 items-center">
          <select className={input} value={cloudProvider} onChange={(e) => setCloudProvider(e.target.value)}>
            {PROVIDERS.map((p) => <option key={p}>{p}</option>)}
          </select>
          <input className={`${input} flex-1`} placeholder="cloud model (gpt-4o…)" value={cloudModel} onChange={(e) => setCloudModel(e.target.value)} />
          <button className={btn} disabled={!cloudModel} onClick={() => call("/api/models/cloud", { provider: cloudProvider, model: cloudModel }, "cloud model set")}>Set cloud</button>
        </div>

        <div className="flex gap-2 items-center">
          <select className={input} value={hybridAgent} onChange={(e) => setHybridAgent(e.target.value)}>
            <option value="">per-agent…</option>
            {agents.map((a) => <option key={a}>{a}</option>)}
          </select>
          <select className={input} value={cloudProvider} onChange={(e) => setCloudProvider(e.target.value)}>
            {PROVIDERS.map((p) => <option key={p}>{p}</option>)}
          </select>
          <button className={btn} disabled={!hybridAgent || !cloudModel} onClick={() => call("/api/models/hybrid", { agent: hybridAgent, provider: cloudProvider, model: cloudModel }, `override set for ${hybridAgent}`)}>Override</button>
        </div>

        <div className="flex gap-2 items-center">
          <select className={input} value={authProvider} onChange={(e) => setAuthProvider(e.target.value)}>
            {PROVIDERS.map((p) => <option key={p}>{p}</option>)}
          </select>
          <input className={`${input} flex-1`} type="password" placeholder="API key (write-only)" value={authKey} onChange={(e) => setAuthKey(e.target.value)} />
          <button className={btn} disabled={!authKey} onClick={() => call("/api/models/auth", { provider: authProvider, api_key: authKey }, "key stored")}>Store key</button>
        </div>

        {Object.keys(cfg.agent_overrides ?? {}).length > 0 && (
          <div className="text-[11px] text-slate-500">
            overrides: {Object.entries(cfg.agent_overrides).map(([a, v]) => `${a}→${v}`).join(", ")}
          </div>
        )}
        {msg && <div className={msg.ok ? "text-emerald-400" : "text-rose-400"}>{msg.text}</div>}
      </div>
    </Panel>
  );
}
