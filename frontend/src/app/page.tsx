"use client";
import useSWR from "swr";
import { api, fetcher } from "@/lib/api";
import Link from "next/link";
import { useState } from "react";
import { useRouter } from "next/navigation";

type Inv = { id: string; name: string; status: string; updated_at: string };
type Integ = { name: string; configured: boolean; last_error: string };
type Finding = { id: string; investigation_id: string; module: string; source: string;
                 kind: string; confidence: number; collected_at: string };

export default function Dashboard() {
  const inv = useSWR<Inv[]>("/api/investigations", fetcher);
  const integ = useSWR<Integ[]>("/api/integrations", fetcher);
  const recent = useSWR<Finding[]>("/api/recent?limit=20", fetcher, { refreshInterval: 5000 });
  const router = useRouter();
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState<any | null>(null);
  const [triageVal, setTriageVal] = useState("");
  const [triageBusy, setTriageBusy] = useState(false);
  async function runHealthCheck() {
    setChecking(true);
    try { setCheckResult(await api("/api/sources/check", { method: "POST" })); }
    finally { setChecking(false); integ.mutate(); }
  }
  async function doTriage() {
    if (!triageVal.trim()) return;
    setTriageBusy(true);
    try {
      const r = await api<{ investigation_id: string }>(
        "/api/triage", { method: "POST", body: JSON.stringify({ value: triageVal.trim() }) });
      router.push(`/investigations/${r.investigation_id}`);
    } catch (e) { alert(String(e)); } finally { setTriageBusy(false); }
  }
  const invs = inv.data ?? [];
  const integs = integ.data ?? [];
  const configured = integs.filter(i => i.configured).length;
  const stats = [
    { label: "investigations",  value: invs.length },
    { label: "active",          value: invs.filter(i => i.status === "running").length },
    { label: "completed",       value: invs.filter(i => i.status === "completed").length },
    { label: "sources online",  value: `${configured}/${integs.length}` },
  ];
  return (
    <div className="space-y-6">
      <div className="card p-3 flex gap-2 items-center">
        <input className="input flex-1" placeholder="quick triage — paste any domain / ip / email / url / hash / cve / btc / eth / phone"
               value={triageVal} onChange={e => setTriageVal(e.target.value)}
               onKeyDown={e => e.key === "Enter" && doTriage()} />
        <button className="btn-primary" onClick={doTriage} disabled={triageBusy || !triageVal.trim()}>
          {triageBusy ? "running…" : "triage"}
        </button>
      </div>
      <div className="grid grid-cols-4 gap-4">
        {stats.map(s => (
          <div key={s.label} className="card p-4">
            <div className="text-mute text-xs font-mono uppercase">{s.label}</div>
            <div className="text-ink font-mono text-2xl mt-1">{s.value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="card p-4 col-span-2">
          <div className="flex items-center justify-between mb-3">
            <div className="font-mono text-sm text-mute uppercase">recent investigations</div>
            <Link href="/investigations" className="btn-primary">new investigation</Link>
          </div>
          <table className="w-full text-sm font-mono">
            <thead className="text-mute text-left">
              <tr><th className="py-1">name</th><th>status</th><th>updated</th><th></th></tr>
            </thead>
            <tbody>
              {invs.slice(0, 10).map(i => (
                <tr key={i.id} className="border-t border-line">
                  <td className="py-1">{i.name}</td>
                  <td><span className="badge">{i.status}</span></td>
                  <td className="text-mute">{new Date(i.updated_at).toLocaleString()}</td>
                  <td><Link className="text-acc" href={`/investigations/${i.id}`}>open →</Link></td>
                </tr>
              ))}
              {invs.length === 0 && <tr><td colSpan={4} className="text-mute py-4">no investigations yet</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="card p-4">
          <div className="font-mono text-sm text-mute uppercase mb-3">recent findings</div>
          <ul className="space-y-1 text-xs font-mono max-h-64 overflow-auto scroll-thin">
            {(recent.data ?? []).map(f => (
              <li key={f.id} className="flex gap-2 items-baseline">
                <span className="text-mute w-16 shrink-0">{new Date(f.collected_at).toLocaleTimeString()}</span>
                <span className="badge shrink-0">{f.source}</span>
                <Link className="text-acc truncate" href={`/investigations/${f.investigation_id}`}>
                  {f.kind}
                </Link>
              </li>
            ))}
            {!(recent.data ?? []).length && <li className="text-mute">no findings yet.</li>}
          </ul>
        </div>
        <div className="card p-4">
          <div className="flex justify-between items-center mb-3">
            <div className="font-mono text-sm text-mute uppercase">source health</div>
            <button className="btn" onClick={runHealthCheck} disabled={checking}>
              {checking ? "checking…" : "ping sources"}
            </button>
          </div>
          {checkResult && (
            <div className="text-xs font-mono text-mute mb-2">
              last run {new Date(checkResult.at).toLocaleTimeString()} —{" "}
              {checkResult.results.filter((r: any) => r.ok).length}/{checkResult.checked} ok
            </div>
          )}
          <ul className="space-y-1 text-sm font-mono max-h-96 overflow-auto scroll-thin">
            {integs.map(i => (
              <li key={i.name} className="flex justify-between">
                <span>{i.name}</span>
                <span className={i.configured ? "text-ok" : "text-mute"}>{i.configured ? "configured" : "unconfigured"}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
