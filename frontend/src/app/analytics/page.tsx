"use client";
import useSWR from "swr";
import { useState } from "react";
import { fetcher } from "@/lib/api";

type A = {
  days: number; finding_count: number; job_count: number;
  findings_per_day: { date: string; count: number }[];
  top_modules: { module: string; count: number }[];
  top_sources: { source: string; count: number }[];
  jobs_by_status: Record<string, number>;
};

export default function Analytics() {
  const [days, setDays] = useState(14);
  const { data } = useSWR<A>(`/api/analytics?days=${days}`, fetcher, { refreshInterval: 30000 });
  const series = data?.findings_per_day ?? [];
  const max = series.reduce((m, p) => Math.max(m, p.count), 0) || 1;
  const W = 760, H = 180, pad = 24;
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="font-mono text-xl">analytics</h1>
        <div className="flex gap-2 items-center font-mono text-sm">
          <span className="text-mute">days</span>
          {[7, 14, 30, 90].map(n => (
            <button key={n} className={"btn " + (days === n ? "text-acc border-acc" : "")}
                    onClick={() => setDays(n)}>{n}</button>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-3 gap-4">
        <div className="card p-4">
          <div className="text-mute text-xs uppercase font-mono">findings</div>
          <div className="text-ink text-3xl font-mono">{data?.finding_count ?? 0}</div>
        </div>
        <div className="card p-4">
          <div className="text-mute text-xs uppercase font-mono">jobs</div>
          <div className="text-ink text-3xl font-mono">{data?.job_count ?? 0}</div>
        </div>
        <div className="card p-4">
          <div className="text-mute text-xs uppercase font-mono">job status</div>
          <ul className="text-sm font-mono mt-1">
            {Object.entries(data?.jobs_by_status ?? {}).map(([k, v]) => (
              <li key={k} className="flex justify-between"><span>{k}</span><span className="text-acc">{v as number}</span></li>
            ))}
          </ul>
        </div>
      </div>

      <div className="card p-4">
        <div className="font-mono text-mute text-xs uppercase mb-2">findings per day</div>
        {series.length === 0 ? <div className="text-mute text-sm font-mono">no activity</div> : (
          <svg viewBox={`0 0 ${W} ${H}`} width="100%" className="font-mono">
            {series.map((p, i) => {
              const x = pad + (i * (W - 2 * pad)) / Math.max(series.length - 1, 1);
              const y = H - pad - ((p.count / max) * (H - 2 * pad));
              return <circle key={p.date} cx={x} cy={y} r="2.5" fill="#7dd3fc" />;
            })}
            <polyline fill="none" stroke="#7dd3fc55" strokeWidth="1.5"
                      points={series.map((p, i) => {
                        const x = pad + (i * (W - 2 * pad)) / Math.max(series.length - 1, 1);
                        const y = H - pad - ((p.count / max) * (H - 2 * pad));
                        return `${x},${y}`;
                      }).join(" ")} />
            {/* axis labels */}
            <text x={pad} y={H - 4} fill="#8a93a3" fontSize="10">{series[0]?.date}</text>
            <text x={W - pad - 70} y={H - 4} fill="#8a93a3" fontSize="10">{series[series.length - 1]?.date}</text>
          </svg>
        )}
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="card p-4">
          <div className="font-mono text-mute text-xs uppercase mb-2">top modules</div>
          <ul className="text-sm font-mono space-y-1 max-h-72 overflow-auto scroll-thin">
            {(data?.top_modules ?? []).map(r => (
              <li key={r.module} className="flex justify-between"><span>{r.module}</span><span className="text-acc">{r.count}</span></li>
            ))}
          </ul>
        </div>
        <div className="card p-4">
          <div className="font-mono text-mute text-xs uppercase mb-2">top sources</div>
          <ul className="text-sm font-mono space-y-1 max-h-72 overflow-auto scroll-thin">
            {(data?.top_sources ?? []).map(r => (
              <li key={r.source} className="flex justify-between"><span>{r.source}</span><span className="text-acc">{r.count}</span></li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
