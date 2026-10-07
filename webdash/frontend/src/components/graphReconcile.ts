import { GraphLink, GraphNode, GraphResp } from "../api";

/**
 * react-force-graph mutates each node object in place to store simulation
 * state (x/y/vx/vy/fx/fy) and rewrites link.source/target from id strings into
 * node references. Two rules follow:
 *
 *  1. Reuse the SAME node/link object instances across polls so surviving nodes
 *     keep their positions and the sim doesn't restart them.
 *  2. Only hand back a NEW top-level {nodes, links} reference when the node set,
 *     link set, or a node's type actually changes — the library reheats its
 *     force simulation on every reference change, so a no-op poll returning a
 *     fresh reference is what makes the graph twitch continuously.
 *
 * `ReconcileState` holds the caches between calls; create one per component
 * instance (via useRef) and pass it back on each reconcile.
 */
export interface RfNode extends GraphNode {
  // Simulation coords the force engine writes in place. Present after first tick.
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

export interface RfLink extends Omit<GraphLink, "source" | "target"> {
  // source/target become node references after ingestion; keep them untouched.
  source: string | RfNode;
  target: string | RfNode;
}

export interface GraphData {
  nodes: RfNode[];
  links: RfLink[];
}

export interface ReconcileState {
  nodesById: Map<string, RfNode>;
  linksByKey: Map<string, RfLink>;
  sig: string;
  data: GraphData;
}

export function createReconcileState(): ReconcileState {
  return {
    nodesById: new Map(),
    linksByKey: new Map(),
    sig: "",
    data: { nodes: [], links: [] },
  };
}

const linkKey = (l: GraphLink): string => `${l.source} ${l.target}`;

/**
 * Reconcile a freshly-polled graph into a stable GraphData.
 *
 * Returns `state.data` unchanged (same reference) when nothing structural
 * changed, so callers can pass the result straight to <ForceGraph2D graphData>
 * without reheating the simulation on identical polls.
 */
export function reconcileGraph(state: ReconcileState, graph: GraphResp | null): GraphData {
  if (!graph) return state.data;

  // Signature keys on node id+type and link endpoints — the things that change
  // the rendered graph. Sorted so ordering differences don't force a rebuild.
  const nodeSig = graph.nodes
    .map((n) => `${n.id}:${n.type ?? ""}`)
    .sort()
    .join(",");
  const linkSig = graph.links.map(linkKey).sort().join(",");
  const sig = `${nodeSig}|${linkSig}`;
  if (sig === state.sig && state.data.nodes.length > 0) return state.data;

  // Reconcile nodes: reuse existing instances (keeps x/y), refresh metadata.
  const seenNodes = new Set<string>();
  const nodes = graph.nodes.map((n) => {
    seenNodes.add(n.id);
    const existing = state.nodesById.get(n.id);
    if (existing) {
      Object.assign(existing, n); // n has no x/y, so positions survive
      return existing;
    }
    const fresh: RfNode = { ...n };
    state.nodesById.set(n.id, fresh);
    return fresh;
  });
  for (const id of state.nodesById.keys()) {
    if (!seenNodes.has(id)) state.nodesById.delete(id);
  }

  // Reconcile links: reuse existing instances by endpoint key. Never re-copy
  // fields onto them — link.source/target may already be resolved node refs.
  const seenLinks = new Set<string>();
  const links = graph.links.map((l) => {
    const key = linkKey(l);
    seenLinks.add(key);
    const existing = state.linksByKey.get(key);
    if (existing) return existing;
    const fresh: RfLink = { ...l };
    state.linksByKey.set(key, fresh);
    return fresh;
  });
  for (const key of state.linksByKey.keys()) {
    if (!seenLinks.has(key)) state.linksByKey.delete(key);
  }

  state.sig = sig;
  state.data = { nodes, links };
  return state.data;
}
