import { useEffect, useState } from "react";
import { apiGet, apiPost, type N8nStatus, type RunResp } from "../api";
import { Badge, Panel } from "./Panel";

type Domain = "red" | "blue" | "purple";

export function N8nView() {
  const [status, setStatus] = useState<N8nStatus | null>(null);
  const [statusErr, setStatusErr] = useState("");

  const [domain, setDomain] = useState<Domain>("purple");
  const [target, setTarget] = useState("");
  const [task, setTask] = useState("Full assessment");
  const [callbackUrl, setCallbackUrl] = useState("");
  const [brainTier, setBrainTier] = useState<"local" | "expensive">("local");
  const [stealth, setStealth] = useState(false);

  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<RunResp | null>(null);
  const [runErr, setRunErr] = useState("");

  useEffect(() => {
    apiGet<N8nStatus>("/api/n8n/status")
      .then(setStatus)
      .catch((e) => setStatusErr(e.message));
  }, []);

  async function submit() {
    setPending(true);
    setRunErr("");
    setResult(null);
    try {
      const body = {
        domain,
        target: target.trim(),
        task: task.trim() || "Full assessment",
        stealth,
        brain_tier: brainTier,
        callback_url: callbackUrl.trim() || null,
        confirm: true, // explicit HITL: operator pressed Confirm & Trigger
      };
      const r = await apiPost<RunResp>("/api/n8n/trigger", body);
      setResult(r);
    } catch (e) {
      setRunErr(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(false);
    }
  }

  const canSubmit = target.trim().length > 0 && !pending;

  return (
    <div className="h-full overflow-auto flex flex-col gap-3">
      <Panel
        title="n8n integration"
        right={
          status ? (
            status.allowlist_configured ? (
              <Badge ok={true}>
                callback allowlist: {status.allowlist_count} host(s)
              </Badge>
            ) : (
              <span className="font-mono text-[10px] uppercase tracking-widest text-dim">
                callback allowlist: not configured
              </span>
            )
          ) : (
            <span className="font-mono text-[10px] uppercase tracking-widest text-dim">
              loading…
            </span>
          )
        }
      >
        {statusErr ? (
          <Badge ok={false}>{statusErr}</Badge>
        ) : (
          <p className="text-dim text-xs leading-relaxed">
            External orchestrators POST to{" "}
            <code className="text-amber">{status?.trigger_path ?? "/api/n8n/trigger"}</code>{" "}
            to launch an engagement. A callback URL is optional; when set it must be an
            approved host in the <code className="text-amber">N8N_WEBHOOK_ALLOWLIST</code>{" "}
            or the trigger is rejected.
          </p>
        )}
      </Panel>

      <Panel title="trigger engagement">
        <div className="flex flex-col gap-3">
          <div className="flex gap-2">
            {(["red", "blue", "purple"] as Domain[]).map((d) => (
              <button
                key={d}
                onClick={() => setDomain(d)}
                className={`px-3 py-1 font-display uppercase tracking-widest text-[11px] border ${
                  domain === d
                    ? "border-amber text-amber"
                    : "border-line text-dim hover:text-amber"
                }`}
              >
                {d}
              </button>
            ))}
          </div>

          <label className="flex flex-col gap-1 text-[11px] uppercase tracking-widest text-dim">
            target
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="10.0.0.0/24 or host"
              className="bg-surface border border-line px-2 py-1 text-amber font-mono text-xs"
            />
          </label>

          <label className="flex flex-col gap-1 text-[11px] uppercase tracking-widest text-dim">
            task
            <input
              value={task}
              onChange={(e) => setTask(e.target.value)}
              className="bg-surface border border-line px-2 py-1 text-amber font-mono text-xs"
            />
          </label>

          <label className="flex flex-col gap-1 text-[11px] uppercase tracking-widest text-dim">
            callback url (optional)
            <input
              value={callbackUrl}
              onChange={(e) => setCallbackUrl(e.target.value)}
              placeholder="https://n8n.corp.local/webhook/…"
              className="bg-surface border border-line px-2 py-1 text-amber font-mono text-xs"
            />
          </label>

          <div className="flex items-center gap-4 text-[11px] uppercase tracking-widest text-dim">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={stealth}
                onChange={(e) => setStealth(e.target.checked)}
              />
              stealth
            </label>
            <label className="flex items-center gap-2">
              brain
              <select
                value={brainTier}
                onChange={(e) => setBrainTier(e.target.value as "local" | "expensive")}
                className="bg-surface border border-line px-2 py-1 text-amber font-mono text-xs"
              >
                <option value="local">local</option>
                <option value="expensive">expensive</option>
              </select>
            </label>
          </div>

          <button
            onClick={submit}
            disabled={!canSubmit}
            className="self-start px-4 py-1.5 font-display uppercase tracking-widest text-[11px] border border-redteam text-redteam hover:bg-redteam/10 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {pending ? "triggering…" : "confirm & trigger"}
          </button>

          {runErr && <Badge ok={false}>{runErr}</Badge>}
          {result && (
            <Badge ok={true}>
              run {result.run_id} — {result.status}
            </Badge>
          )}
        </div>
      </Panel>
    </div>
  );
}
