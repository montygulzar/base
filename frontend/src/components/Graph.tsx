"use client";
import { useEffect, useMemo, useState } from "react";
import useSWR from "swr";
import ReactFlow, { Background, Controls, MiniMap, Node, Edge } from "reactflow";
import "reactflow/dist/style.css";
import { fetcher } from "@/lib/api";

type Graph = { nodes: any[]; edges: any[] };

const COLORS: Record<string, string> = {
  domain: "#7dd3fc", ip: "#f59e0b", email: "#22c55e", username: "#a78bfa",
  url: "#38bdf8", org: "#f472b6", asn: "#eab308", cve: "#ef4444",
  cert: "#2dd4bf", file: "#94a3b8", hash: "#94a3b8",
};

export default function GraphView({ investigationId }: { investigationId: string }) {
  const { data } = useSWR<Graph>(`/api/graph/${investigationId}`, fetcher, { refreshInterval: 4000 });
  const [filter, setFilter] = useState<string>("");
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
      <div className="flex-1">
        <ReactFlow nodes={nodes} edges={edges} fitView>
          <Background color="#1c212c" gap={16} />
          <Controls />
          <MiniMap nodeColor={() => "#242b38"} maskColor="rgba(11,13,18,.7)" />
        </ReactFlow>
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
