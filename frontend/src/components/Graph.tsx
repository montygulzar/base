"use client";
import { useEffect, useMemo, useState } from "react";
import useSWR from "swr";
import ReactFlow, { Background, Controls, MiniMap, Node, Edge } from "reactflow";
import "reactflow/dist/style.css";
import dagre from "dagre";
import { api, fetcher } from "@/lib/api";

type Graph = { nodes: any[]; edges: any[] };

const COLORS: Record<string, string> = {
  domain: "#7dd3fc", ip: "#f59e0b", email: "#22c55e", username: "#a78bfa",
  url: "#38bdf8", org: "#f472b6", asn: "#eab308", cve: "#ef4444",
  cert: "#2dd4bf", file: "#94a3b8", hash: "#94a3b8",
};

export default function GraphView({ investigationId }: { investigationId: string }) {
  const { data, mutate } = useSWR<Graph>(`/api/graph/${investigationId}`, fetcher, { refreshInterval: 4000 });
  const [filter, setFilter] = useState<string>("");
  const [sel, setSel] = useState<any | null>(null);

  async function expand(entityId: string, modules: string[] | null = null) {
    await api(`/api/transforms/${investigationId}/expand/${entityId}`, {
      method: "POST", body: JSON.stringify(modules),
    });
    setTimeout(() => mutate(), 2000);
  }
  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [], edges: [] };
    const kept = data.nodes.filter(n => !filter || n.value.toLowerCase().includes(filter.toLowerCase()) || n.type === filter);
    const keptIds = new Set(kept.map(k => k.id));
    const positions = layout(kept, data.edges.filter(e => keptIds.has(e.src) && keptIds.has(e.dst)));
    const nn: Node[] = kept.map(n => ({
      id: n.id, position: positions[n.id] ?? { x: 0, y: 0 },
      data: { label: `${n.type}:${n.value.slice(0, 30)}` },
      style: {
        background: "#11141b", color: "#d9dde3",
        border: `1px solid ${COLORS[n.type] ?? "#242b38"}`,
        fontFamily: "ui-monospace,monospace", fontSize: 11, padding: 6, borderRadius: 6,
        width: 220,
      },
    }));
    const ee: Edge[] = data.edges
      .filter(e => keptIds.has(e.src) && keptIds.has(e.dst))
      .map(e => ({
        id: e.id, source: e.src, target: e.dst, label: e.type,
        style: { stroke: "#2b3240" },
        labelStyle: { fill: "#8a93a3", fontFamily: "ui-monospace,monospace", fontSize: 10 },
      }));
    return { nodes: nn, edges: ee };
  }, [data, filter]);

  return (
    <div className="h-full w-full flex flex-col">
      <div className="p-2 border-b border-line flex gap-2 items-center">
        <input className="input" placeholder="filter by value or type" value={filter} onChange={e => setFilter(e.target.value)} />
        <div className="text-mute text-xs font-mono">
          {data?.nodes.length ?? 0} nodes • {data?.edges.length ?? 0} edges
        </div>
      </div>
      <div className="flex-1 relative">
        <ReactFlow nodes={nodes} edges={edges} fitView
                   onNodeClick={(_, n) => setSel(data?.nodes.find(x => x.id === n.id) ?? null)}>
          <Background color="#1c212c" gap={16} />
          <Controls />
          <MiniMap nodeColor={() => "#242b38"} maskColor="rgba(11,13,18,.7)" />
        </ReactFlow>
        {sel && (
          <div className="absolute top-2 right-2 card p-3 w-72 text-xs font-mono">
            <div className="flex justify-between">
              <div><span className="text-mute">{sel.type}</span> <span className="text-acc">{sel.value}</span></div>
              <button className="text-mute" onClick={() => setSel(null)}>×</button>
            </div>
            <div className="text-mute mt-1">confidence {sel.confidence.toFixed(2)}</div>
            <pre className="mt-2 whitespace-pre-wrap text-ink/80 max-h-32 overflow-auto">{JSON.stringify(sel.attributes, null, 2)}</pre>
            {["domain","ip","url","email","username"].includes(sel.type) && (
              <button className="btn-primary w-full mt-2" onClick={() => expand(sel.id)}>expand (run modules)</button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function layout(nodes: any[], edges: any[]): Record<string, { x: number; y: number }> {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: 24, ranksep: 90, marginx: 12, marginy: 12 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach(n => g.setNode(n.id, { width: 220, height: 32 }));
  edges.forEach(e => g.setEdge(e.src, e.dst));
  dagre.layout(g);
  const out: Record<string, { x: number; y: number }> = {};
  nodes.forEach(n => {
    const p = g.node(n.id);
    if (p) out[n.id] = { x: p.x - 110, y: p.y - 16 };
  });
  return out;
}
