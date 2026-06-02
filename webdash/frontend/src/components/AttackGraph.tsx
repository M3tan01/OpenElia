import { useEffect, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { apiGet, GraphResp } from "../api";
import { Panel } from "./Panel";

const NODE_COLOR: Record<string, string> = {
  host: "#ffb000", // amber — assets
  service: "#3ec6ff", // blue — services
  vulnerability: "#ff414d", // red — vulns
  credential: "#c084fc", // purple — creds
};

export function AttackGraph() {
  const [graph, setGraph] = useState<GraphResp | null>(null);
  const wrap = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 400, h: 300 });

  useEffect(() => {
    const load = () => apiGet<GraphResp>("/api/graph").then(setGraph).catch(() => {});
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (!wrap.current) return;
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: e.contentRect.height }));
    ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  const data = graph
    ? { nodes: graph.nodes.map((n) => ({ ...n })), links: graph.links.map((l) => ({ ...l })) }
    : { nodes: [], links: [] };

  return (
    <Panel
      title="Attack Surface"
      right={<span className="text-[10px] text-slate-500">{graph ? `${graph.summary.hosts}h / ${graph.summary.services}s / ${graph.summary.vulnerabilities}v` : ""}</span>}
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
          />
        ) : (
          <div className="text-xs text-slate-600 italic">no attack-surface data yet</div>
        )}
      </div>
    </Panel>
  );
}
