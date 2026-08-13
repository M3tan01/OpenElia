// Catalog of panels the user can compose onto the main C2 console.
// Each entry reuses an existing self-contained view component. Panels that need
// shared live data (snapshot / stream / refresh) receive it via PanelCtx; the
// rest fetch their own. Adding a panel here makes it available in the customizer.

import type { ReactNode } from "react";
import type { StateResp, StreamState } from "./api";
import { AgentActivity } from "./components/AgentActivity";
import { AttackGraph } from "./components/AttackGraph";
import { AuditTimeline } from "./components/AuditTimeline";
import { CleanupView } from "./components/CleanupView";
import { ControlBar } from "./components/ControlBar";
import { CostMitre } from "./components/CostMitre";
import { EngagementsView } from "./components/EngagementsView";
import { FindingsView } from "./components/FindingsView";
import { ModelSelector } from "./components/ModelSelector";
import { PurpleCoverageView } from "./components/PurpleCoverageView";
import { RoEView } from "./components/RoEView";

export type PanelCtx = {
  snapshot: StateResp | null;
  stream: StreamState;
  refresh: () => void;
};

export type PanelSpan = "full" | "wide" | "normal";

export type PanelDef = {
  id: string;
  label: string;
  span: PanelSpan;
  render: (ctx: PanelCtx) => ReactNode;
};

export const PANEL_CATALOG: PanelDef[] = [
  { id: "control",  label: "Control",          span: "full",   render: (c) => <ControlBar snapshot={c.snapshot} onChange={c.refresh} /> },
  { id: "agents",   label: "Agent Activity",   span: "normal", render: (c) => <AgentActivity liveTasks={c.stream.tasks} /> },
  { id: "graph",    label: "Attack Surface Graph", span: "wide", render: () => <AttackGraph /> },
  { id: "audit",    label: "Audit Timeline",   span: "normal", render: (c) => <AuditTimeline liveAudit={c.stream.audit} /> },
  { id: "models",   label: "Brain Models",     span: "wide",   render: () => <ModelSelector /> },
  { id: "cost",     label: "Cost & MITRE",     span: "wide",   render: () => <CostMitre /> },
  { id: "coverage", label: "Purple Coverage",  span: "wide",   render: () => <PurpleCoverageView /> },
  { id: "findings", label: "Findings",         span: "normal", render: () => <FindingsView /> },
  { id: "cleanup",  label: "Rollback Queue",   span: "normal", render: () => <CleanupView /> },
  { id: "sessions", label: "Sessions",         span: "normal", render: () => <EngagementsView /> },
  { id: "roe",      label: "RoE / Scope",      span: "normal", render: () => <RoEView /> },
];

export const PANEL_BY_ID: Record<string, PanelDef> = Object.fromEntries(
  PANEL_CATALOG.map((p) => [p.id, p]),
);

// The out-of-box layout (mirrors the original fixed C2 console).
export const DEFAULT_LAYOUT: string[] = ["control", "agents", "graph", "audit", "models", "cost"];

const SPAN_CLASS: Record<PanelSpan, string> = {
  full:   "lg:col-span-4",
  wide:   "lg:col-span-2",
  normal: "lg:col-span-1",
};

export function spanClass(span: PanelSpan): string {
  return SPAN_CLASS[span];
}
