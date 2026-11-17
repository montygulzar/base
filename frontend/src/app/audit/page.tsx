"use client";
import useSWR from "swr";
import { fetcher } from "@/lib/api";

type Row = { id: number; user_id: string | null; action: string; target: string; detail: any; at: string };

export default function Audit() {
  const { data, error } = useSWR<Row[]>("/api/audit?limit=500", fetcher, { refreshInterval: 3000 });
  return (
    <div className="space-y-4">
      <h1 className="font-mono text-xl">audit log</h1>
      {error && <div className="text-err text-sm font-mono">admin only — {error.message}</div>}
      <div className="card">
        <table className="w-full text-xs font-mono">
          <thead className="text-mute text-left">
            <tr><th className="p-2">time</th><th>user</th><th>action</th><th>target</th><th>detail</th></tr>
          </thead>
          <tbody>
            {(data ?? []).map(r => (
              <tr key={r.id} className="border-t border-line align-top">
                <td className="p-2 text-mute">{new Date(r.at).toLocaleString()}</td>
                <td>{r.user_id?.slice(0,8)}…</td>
                <td><span className="badge">{r.action}</span></td>
                <td>{r.target.slice(0,8)}…</td>
                <td><pre className="whitespace-pre-wrap">{JSON.stringify(r.detail)}</pre></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
