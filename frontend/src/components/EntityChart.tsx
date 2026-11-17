"use client";
import useSWR from "swr";
import { fetcher } from "@/lib/api";

type Stats = { entities_by_type: Record<string, number> };

const COLORS: Record<string, string> = {
  domain: "#7dd3fc", ip: "#f59e0b", email: "#22c55e", username: "#a78bfa",
  url: "#38bdf8", org: "#f472b6", asn: "#eab308", cve: "#ef4444",
  cert: "#2dd4bf", file: "#94a3b8", hash: "#94a3b8", phone: "#fca5a5",
  ttp: "#c084fc",
};

export default function EntityChart({ invId }: { invId: string }) {
  const { data } = useSWR<Stats>(`/api/stats/${invId}`, fetcher, { refreshInterval: 4000 });
  const dict = data?.entities_by_type ?? {};
  const rows = Object.entries(dict).sort((a, b) => b[1] - a[1]);
  const max = rows.reduce((m, [, v]) => Math.max(m, v), 0);
  const W = 420;
  const RowH = 18;
  const H = Math.max(RowH * rows.length + 8, 40);
  return (
    <div className="card p-3">
      <div className="font-mono text-mute text-xs uppercase mb-2">entities by type</div>
      {!rows.length ? <div className="text-mute text-sm font-mono">no entities yet</div> : (
        <svg width="100%" viewBox={`0 0 ${W} ${H}`} className="font-mono">
          {rows.map(([k, v], i) => {
            const y = i * RowH + 4;
            const width = max ? Math.max(1, (v / max) * (W - 140)) : 1;
            return (
              <g key={k}>
                <text x="4" y={y + 12} fill="#8a93a3" fontSize="11">{k}</text>
                <rect x="100" y={y + 2} width={width} height={RowH - 6}
                      fill={COLORS[k] ?? "#242b38"} rx="2" />
                <text x={102 + width + 4} y={y + 12} fill="#d9dde3" fontSize="11">{v}</text>
              </g>
            );
          })}
        </svg>
      )}
    </div>
  );
}
