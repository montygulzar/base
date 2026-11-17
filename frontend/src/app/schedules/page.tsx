"use client";
import useSWR from "swr";
import { useState } from "react";
import { api, fetcher } from "@/lib/api";
import Link from "next/link";

type Inv = { id: string; name: string };
type Sch = { id: string; investigation_id: string; interval_seconds: number;
             modules: any; enabled: boolean; last_run_at: string | null;
             next_run_at: string | null };

export default function Schedules() {
  const invs = useSWR<Inv[]>("/api/investigations", fetcher);
  const schs = useSWR<Sch[]>("/api/schedules", fetcher, { refreshInterval: 5000 });
  const [invId, setInvId] = useState("");
  const [interval, setInterval] = useState(86400);
  async function create() {
    if (!invId) return;
    await api("/api/schedules", { method: "POST",
      body: JSON.stringify({ investigation_id: invId, interval_seconds: Number(interval) }) });
    setInvId(""); schs.mutate();
  }
  async function toggle(id: string) { await api(`/api/schedules/${id}/toggle`, { method: "POST" }); schs.mutate(); }
  async function del(id: string) { await api(`/api/schedules/${id}`, { method: "DELETE" }); schs.mutate(); }
  return (
    <div className="space-y-4">
      <h1 className="font-mono text-xl">schedules</h1>
      <div className="card p-4 flex gap-2 items-end">
        <div>
          <div className="text-mute text-xs font-mono">investigation</div>
          <select className="input" value={invId} onChange={e => setInvId(e.target.value)}>
            <option value="">—</option>
            {(invs.data ?? []).map(i => <option key={i.id} value={i.id}>{i.name}</option>)}
          </select>
        </div>
        <div>
          <div className="text-mute text-xs font-mono">interval (s)</div>
          <input type="number" className="input w-28" value={interval} onChange={e => setInterval(+e.target.value)} />
        </div>
        <button className="btn-primary" onClick={create} disabled={!invId}>add schedule</button>
      </div>
      <div className="card">
        <table className="w-full text-sm font-mono">
          <thead className="text-mute text-left">
            <tr><th className="p-3">investigation</th><th>interval</th><th>enabled</th><th>next run</th><th>last run</th><th></th></tr>
          </thead>
          <tbody>
            {(schs.data ?? []).map(s => (
              <tr key={s.id} className="border-t border-line">
                <td className="p-3"><Link className="text-acc" href={`/investigations/${s.investigation_id}`}>{s.investigation_id.slice(0,8)}…</Link></td>
                <td>{s.interval_seconds}s</td>
                <td>{s.enabled ? "yes" : "no"}</td>
                <td className="text-mute">{s.next_run_at ? new Date(s.next_run_at).toLocaleString() : "—"}</td>
                <td className="text-mute">{s.last_run_at ? new Date(s.last_run_at).toLocaleString() : "—"}</td>
                <td className="p-3 space-x-2">
                  <button className="btn" onClick={() => toggle(s.id)}>toggle</button>
                  <button className="btn" onClick={() => del(s.id)}>delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
