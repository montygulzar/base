"use client";
import { useEffect, useMemo, useState } from "react";
import useSWR from "swr";
import ReactFlow, { Background, Controls, MiniMap, Node, Edge } from "reactflow";
import "reactflow/dist/style.css";
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
    const positions = circular(data.nodes.length);
    const nn: Node[] = data.nodes
      .filter(n => !filter || n.value.toLowerCase().includes(filter.toLowerCase()) || n.type === filter)
      .map((n, i) => ({
        id: n.id, position: positions[i], data: { label: `${n.type}:${n.value.slice(0, 30)}` },
        style: {
          background: "#11141b", color: "#d9dde3",
          border: `1px solid ${COLORS[n.type] ?? "#242b38"}`,
          fontFamily: "ui-monospace,monospace", fontSize: 11, padding: 4, borderRadius: 6,
        },
      }));
    const ee: Edge[] = data.edges.map(e => ({
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

function circular(n: number) {
  const R = Math.max(140, 40 * Math.sqrt(n));
  return Array.from({ length: n }, (_, i) => {
    const a = (2 * Math.PI * i) / Math.max(n, 1);
    return { x: Math.cos(a) * R + R, y: Math.sin(a) * R + R };
  });
}
