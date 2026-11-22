"use client";
import useSWR from "swr";
import { fetcher } from "@/lib/api";

type Row = {
  id: string; type: string; value: string;
  hop: number | null; root_proximity: number | null;
  is_root: boolean; confidence: number;
};

export default function CascadeRanked({ invId }: { invId: string }) {
  const { data } = useSWR<Row[]>(`/api/cascade/${invId}/ranked?limit=100`, fetcher, { refreshInterval: 5000 });
  const rows = data ?? [];
  return (
    <div className="card p-3">
      <div className="font-mono text-mute text-xs uppercase mb-2">
        strongest-linked discoveries ({rows.length}) — sorted by proximity to seed
      </div>
      {!rows.length ? <div className="text-mute text-sm font-mono">run cascade first.</div> : (
        <table className="w-full text-xs font-mono">
          <thead className="text-mute text-left">
            <tr><th className="p-1">hop</th><th>proximity</th><th>type</th><th>value</th></tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.id} className="border-t border-line">
                <td className="p-1">{r.is_root ? <span className="text-acc">root</span> : r.hop}</td>
                <td>
                  <span style={{
                    display:"inline-block", width:"50px",
                    background:"linear-gradient(90deg, var(--bot-p), var(--bot-p))",
                    opacity: Math.max(0.2, r.root_proximity || 0),
                    height:"6px", verticalAlign:"middle", borderRadius:"3px"
                  }}></span>
                  <span className="ml-2">{r.root_proximity?.toFixed(3)}</span>
                </td>
                <td><span className="badge">{r.type}</span></td>
                <td className="break-all">{r.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
