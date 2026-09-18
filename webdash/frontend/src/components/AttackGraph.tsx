import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { apiGet, GraphResp } from "../api";
import { Badge, Panel } from "./Panel";
import { usePoll } from "../usePoll";
import { createReconcileState, reconcileGraph } from "./graphReconcile";

const NODE_COLOR: Record<string, string> = {
  host: "#ffb000", // amber — assets
  service: "#3ec6ff", // blue — services
  vulnerability: "#ff414d", // red — vulns
  credential: "#c084fc", // purple — creds
};

export function AttackGraph() {
  const { data: graph, error } = usePoll<GraphResp>(() => apiGet<GraphResp>("/api/graph"), 5000);
  const wrap = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 400, h: 300 });

  useEffect(() => {
    if (!wrap.current) return;
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: e.contentRect.height }));
    ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  // Reconcile each poll into a reference-stable graphData that preserves node
  // objects (and their live x/y/vx/vy) across updates. Passing a fresh object
  // every render reheats react-force-graph's simulation → the constant twitch.
  const reconcile = useRef(createReconcileState());
  const data = useMemo(() => reconcileGraph(reconcile.current, graph), [graph]);

  return (
    <Panel
      title="Attack Surface Graph"
      right={
        <>
          {error && <Badge ok={false}>offline</Badge>}
          <span className="text-[10px] text-slate-500">{graph ? `${graph.summary.hosts}h / ${graph.summary.services}s / ${graph.summary.vulnerabilities}v` : ""}</span>
        </>
      }
    >
      <div ref={wrap} className="w-full h-full min-h-[240px]">
        {graph && graph.nodes.length > 0 ? (
          <ForceGraph2D
            graphData={data}
            width={size.w}
            height={Math.max(size.h, 240)}
            backgroundColor="#0b0f10"
            nodeColor={(n: any) => NODE_COLOR[n.type] ?? "#5d6b67"}
            nodeLabel={(n: any) => `${n.type}: ${n.id}`}
            nodeRelSize={5}
            linkColor={() => "#2a3a36"}
            linkDirectionalArrowLength={3}
            warmupTicks={40}
            cooldownTicks={80}
          />
        ) : (
          <div className="text-xs text-slate-600 italic">no attack-surface data yet</div>
        )}
      </div>
    </Panel>
  );
}
