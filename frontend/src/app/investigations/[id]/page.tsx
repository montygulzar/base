"use client";
import useSWR from "swr";
import { useEffect, useState } from "react";
import { api, fetcher, API_URL, getToken } from "@/lib/api";
import Graph from "@/components/Graph";
import EntityChart from "@/components/EntityChart";
import ScreenshotGallery from "@/components/ScreenshotGallery";
import GeoMap from "@/components/GeoMap";
import Link from "next/link";

type Job = { id: string; module: string; status: string; error: string; result: any };
type Finding = { id: string; module: string; source: string; kind: string; data: any; confidence: number; collected_at: string };
type Subject = { id: string; type: string; value: string; note: string };

export default function Investigation({ params }: { params: { id: string } }) {
  const id = params.id;
  const inv = useSWR(`/api/investigations/${id}`, fetcher);
  const subs = useSWR<Subject[]>(`/api/investigations/${id}/subjects`, fetcher);
  const jobs = useSWR<Job[]>(`/api/investigations/${id}/jobs`, fetcher, { refreshInterval: 2000 });
  const finds = useSWR<Finding[]>(`/api/investigations/${id}/findings`, fetcher, { refreshInterval: 3000 });

  const [tab, setTab] = useState<"overview"|"findings"|"graph"|"jobs">("overview");
  const [search, setSearch] = useState("");
  const [searchResults, setSearchResults] = useState<Finding[] | null>(null);
  async function doSearch() {
    if (!search) { setSearchResults(null); return; }
    const r = await api<{ hits: Finding[] }>(`/api/search/${id}?q=${encodeURIComponent(search)}`);
    setSearchResults(r.hits);
  }

  async function run() {
    await api(`/api/investigations/${id}/run`, { method: "POST", body: JSON.stringify({}) });
    jobs.mutate();
  }
  const token = getToken();
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-mono text-xl">{inv.data?.name ?? "…"}</h1>
          <div className="text-mute text-xs font-mono">{inv.data?.status}</div>
        </div>
        <div className="flex gap-2">
          <button className="btn-primary" onClick={run}>run collection</button>
          <a className="btn" href={`${API_URL}/api/reports/${id}.md`} target="_blank">md</a>
          <a className="btn" href={`${API_URL}/api/reports/${id}.html`} target="_blank">html</a>
          <a className="btn" href={`${API_URL}/api/reports/${id}.pdf`} target="_blank">pdf</a>
          <a className="btn" href={`${API_URL}/api/reports/${id}.csv`} target="_blank">csv</a>
          <a className="btn" href={`${API_URL}/api/reports/${id}.json`} target="_blank">json</a>
          <a className="btn" href={`${API_URL}/api/misp/${id}.misp.json`} target="_blank">misp</a>
          <a className="btn" href={`${API_URL}/api/stix/${id}.stix.json`} target="_blank">stix</a>
          <a className="btn" href={`${API_URL}/api/exports/${id}.graphml`} target="_blank">graphml</a>
          <a className="btn" href={`${API_URL}/api/exports/${id}.gexf`} target="_blank">gexf</a>
          <a className="btn" href={`${API_URL}/api/geojson/${id}.geojson`} target="_blank">geojson</a>
        </div>
      </div>

      <div className="flex gap-2 border-b border-line">
        {(["overview","findings","graph","jobs"] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
                  className={`px-3 py-2 font-mono text-sm ${tab===t?"text-acc border-b border-acc":"text-mute"}`}>{t}</button>
        ))}
      </div>

      {tab === "overview" && (
        <div className="grid grid-cols-2 gap-4">
          <div className="card p-4">
            <div className="font-mono text-mute text-xs uppercase mb-2">subjects</div>
            <ul className="text-sm font-mono space-y-1">
              {(subs.data ?? []).map(s => (
                <li key={s.id}><span className="badge mr-2">{s.type}</span>{s.value} <span className="text-mute">{s.note}</span></li>
              ))}
            </ul>
            <div className="text-mute text-xs mt-3">
              jobs: {jobs.data?.length ?? 0} • findings: {finds.data?.length ?? 0}
            </div>
          </div>
          <EntityChart invId={id} />
          <div className="col-span-2">
            <ScreenshotGallery invId={id} />
          </div>
          <div className="col-span-2">
            <GeoMap invId={id} />
          </div>
        </div>
      )}

      {tab === "findings" && (
        <div className="space-y-2">
          <div className="flex gap-2">
            <input className="input flex-1" placeholder="search findings…" value={search}
                   onChange={e => setSearch(e.target.value)}
                   onKeyDown={e => e.key === "Enter" && doSearch()} />
            <button className="btn-primary" onClick={doSearch}>search</button>
            {searchResults && <button className="btn" onClick={() => { setSearchResults(null); setSearch(""); }}>clear</button>}
          </div>
        <div className="card">
          <table className="w-full text-xs font-mono">
            <thead className="text-mute text-left">
              <tr><th className="p-2">module</th><th>source</th><th>kind</th><th>conf</th><th>data</th><th>time</th></tr>
            </thead>
            <tbody>
              {(searchResults ?? finds.data ?? []).map(f => (
                <tr key={f.id} className="border-t border-line align-top">
                  <td className="p-2">{f.module}</td>
                  <td>{f.source}</td>
                  <td>{f.kind}</td>
                  <td>{f.confidence.toFixed(2)}</td>
                  <td className="max-w-xl"><pre className="whitespace-pre-wrap text-ink/80">{JSON.stringify(f.data).slice(0, 400)}</pre></td>
                  <td className="text-mute">{new Date(f.collected_at).toLocaleTimeString()}</td>
                </tr>
              ))}
              {((searchResults ?? finds.data) ?? []).length === 0 && <tr><td colSpan={6} className="text-mute p-4">{searchResults ? "no matches." : "no findings yet. click run collection."}</td></tr>}
            </tbody>
          </table>
        </div>
        </div>
      )}

      {tab === "graph" && (
        <div className="card p-0 h-[70vh]"><Graph investigationId={id} /></div>
      )}

      {tab === "jobs" && (
        <div className="card">
          <table className="w-full text-sm font-mono">
            <thead className="text-mute text-left">
              <tr><th className="p-2">module</th><th>status</th><th>error</th><th>result</th></tr>
            </thead>
            <tbody>
              {(jobs.data ?? []).map(j => (
                <tr key={j.id} className="border-t border-line">
                  <td className="p-2">{j.module}</td>
                  <td><span className={`badge ${j.status==="error"?"text-err":j.status==="done"?"text-ok":""}`}>{j.status}</span></td>
                  <td className="text-err">{j.error}</td>
                  <td className="text-mute">{JSON.stringify(j.result)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
