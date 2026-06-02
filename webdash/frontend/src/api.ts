import { useEffect, useRef, useState } from "react";

// --- token: read once from the URL fragment (#token=…), then keep in memory --- //
function readToken(): string {
  // hash is "#token=…" — parse robustly (handles any param order/extra params)
  return new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
}
export const TOKEN = readToken();

const HEADERS = (): HeadersInit => ({
  Authorization: `Bearer ${TOKEN}`,
  "Content-Type": "application/json",
});

export async function apiGet<T>(path: string): Promise<T> {
  const r = await fetch(path, { headers: HEADERS() });
  if (!r.ok) throw new Error(`${r.status} ${(await r.text()).slice(0, 200)}`);
  return r.json() as Promise<T>;
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(path, { method: "POST", headers: HEADERS(), body: JSON.stringify(body) });
  const text = await r.text();
  const data = text ? JSON.parse(text) : {};
  if (!r.ok) throw new Error(data.detail || `${r.status}`);
  return data as T;
}

// --- types -------------------------------------------------------------------- //
export interface Engagement { id: string; target: string; scope: string; started: string; is_locked: boolean; }
export interface Finding { severity: string; title: string; mitre_ttp: string; }
export interface StateResp { engagement?: Engagement; findings?: Finding[]; blue_alerts?: unknown[]; [k: string]: unknown; }
export interface AuditEvent { timestamp: string; source: string; target: string; status: string; reason: string; }
export interface AuditResp { events: AuditEvent[]; count: number; chain_ok: boolean; chain_status: string; chain_msg: string; }
export interface TaskResult { task_id: string; agent_name: string; status: string; completed_at?: string; tokens_used?: number; }
export interface GraphNode { id: string; type?: string; [k: string]: unknown; }
export interface GraphLink { source: string; target: string; relation?: string; }
export interface GraphResp { summary: Record<string, number>; nodes: GraphNode[]; links: GraphLink[]; }
export interface CostResp { summary: { session_cost: number; total_historical_cost: number; budget_remaining: number }; series: { session: string; total_cost: number; calls: number }[]; }
export interface ModelsResp { config: Record<string, unknown>; agents: Record<string, string[]>; }
export type RoEResp = {
  authorized_subnets: string[];
  blacklisted_ips: string[];
  prohibited_tools: string[];
  quiet_hours: string | { start?: string; end?: string } | null;
};

export type EngagementResp = {
  id: string;
  target: string;
  started: string | null;
  current_phase: string | null;
  is_active: boolean;
  is_locked: boolean;
};

export type AdversaryResp = {
  name: string;
  alias: string;
  description: string;
  preferred_ttps: string[];
  tools: string[];
  stealth_required: boolean;
  rationale: string;
};

export type RunResp = { run_id: string; status: string };

export type SystemResp = { gateway: string; active_engagements: number };

// --- live stream -------------------------------------------------------------- //
export interface StreamState {
  connected: boolean;
  snapshot: StateResp | null;
  audit: AuditEvent[];
  tasks: TaskResult[];
}

export function useStream(): StreamState {
  const [state, setState] = useState<StreamState>({ connected: false, snapshot: null, audit: [], tasks: [] });
  const ref = useRef<WebSocket | null>(null);

  useEffect(() => {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    // Token rides in the WebSocket subprotocol (Sec-WebSocket-Protocol header),
    // not the URL — keeps it out of server access logs and browser history.
    const ws = new WebSocket(
      `${proto}://${window.location.host}/api/stream`,
      TOKEN ? [TOKEN] : undefined
    );
    ref.current = ws;

    ws.onopen = () => setState((s) => ({ ...s, connected: true }));
    ws.onclose = () => setState((s) => ({ ...s, connected: false }));
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.type === "snapshot") {
        setState((s) => ({ ...s, snapshot: msg.state }));
      } else if (msg.type === "audit") {
        setState((s) => ({ ...s, audit: [msg.event, ...s.audit].slice(0, 300) }));
      } else if (msg.type === "task") {
        setState((s) => ({ ...s, tasks: [msg.event, ...s.tasks].slice(0, 300) }));
      }
    };
    return () => ws.close();
  }, []);

  return state;
}
