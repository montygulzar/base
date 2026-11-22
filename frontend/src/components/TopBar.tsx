"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api, getToken, setToken } from "@/lib/api";
import { useRouter } from "next/navigation";

type Hit = {
  investigations: { id: string; name: string; status: string }[];
  entities: { id: string; type: string; value: string; investigation_id: string }[];
  findings: { id: string; module: string; source: string; kind: string; investigation_id: string }[];
};

export default function TopBar() {
  const [email, setEmail] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [hits, setHits] = useState<Hit | null>(null);
  const router = useRouter();
  useEffect(() => {
    if (!getToken()) { router.push("/login"); return; }
    api<{ email: string }>("/api/auth/me").then(u => setEmail(u.email)).catch(() => router.push("/login"));
  }, [router]);
  async function run() {
    if (!q.trim()) { setHits(null); setOpen(false); return; }
    const r = await api<Hit>(`/api/global_search?q=${encodeURIComponent(q.trim())}&limit=20`);
    setHits(r); setOpen(true);
  }
  return (
    <header className="h-14 border-b border-line bg-bg px-6 flex items-center justify-between relative">
      <div className="flex items-center gap-2 text-xs text-mute">
        <span className="live-dot" />
        <span>Connected</span>
      </div>
      <div className="relative w-[480px]">
        <input className="input w-full pl-8" placeholder="Search everything — domains, IPs, handles, hashes…"
               value={q} onChange={e => setQ(e.target.value)}
               onKeyDown={e => e.key === "Enter" && run()}
               onBlur={() => setTimeout(() => setOpen(false), 200)} />
        <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-dim text-sm">⌕</span>
        {open && hits && (
          <div className="absolute left-0 right-0 top-11 card max-h-[70vh] overflow-auto scroll-thin text-sm z-50 shadow-2xl">
            {hits.investigations.length > 0 && <div className="px-3 pt-2 pb-1 text-[10px] uppercase tracking-wider text-dim">Investigations</div>}
            {hits.investigations.map(i => (
              <Link key={i.id} href={`/investigations/${i.id}`} className="flex items-center justify-between px-3 py-1.5 hover:bg-soft">
                <span>{i.name}</span>
                <span className="badge">{i.status}</span>
              </Link>
            ))}
            {hits.entities.length > 0 && <div className="px-3 pt-2 pb-1 text-[10px] uppercase tracking-wider text-dim">Entities</div>}
            {hits.entities.map(e => (
              <Link key={e.id} href={`/investigations/${e.investigation_id}`} className="flex items-center gap-2 px-3 py-1.5 hover:bg-soft">
                <span className="badge">{e.type}</span>
                <span className="text-ink truncate">{e.value}</span>
              </Link>
            ))}
            {hits.findings.length > 0 && <div className="px-3 pt-2 pb-1 text-[10px] uppercase tracking-wider text-dim">Findings</div>}
            {hits.findings.map(f => (
              <Link key={f.id} href={`/investigations/${f.investigation_id}`} className="flex items-center gap-2 px-3 py-1.5 hover:bg-soft">
                <span className="badge">{f.source}</span>
                <span className="text-ink">{f.kind}</span>
              </Link>
            ))}
            {!hits.investigations.length && !hits.entities.length && !hits.findings.length && (
              <div className="px-3 py-4 text-center text-mute text-sm">no hits. try fewer characters, or more sinful ones.</div>
            )}
          </div>
        )}
      </div>
      <div className="flex items-center gap-3 text-sm">
        <span className="text-mute">{email?.split("@")[0]}</span>
        <button onClick={() => { setToken(null); router.push("/login"); }} className="btn text-xs">Sign out</button>
      </div>
    </header>
  );
}
