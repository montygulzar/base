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
    <header className="h-12 border-b border-line bg-panel px-6 flex items-center justify-between relative">
      <div className="text-sm font-mono text-mute">intelligence platform</div>
      <div className="relative">
        <input className="input w-80" placeholder="global search (⏎)" value={q}
               onChange={e => setQ(e.target.value)}
               onKeyDown={e => e.key === "Enter" && run()}
               onBlur={() => setTimeout(() => setOpen(false), 200)} />
        {open && hits && (
          <div className="absolute right-0 top-10 w-96 card max-h-96 overflow-auto scroll-thin text-xs font-mono z-50">
            {hits.investigations.length > 0 && <div className="p-2 text-mute uppercase">investigations</div>}
            {hits.investigations.map(i => (
              <Link key={i.id} href={`/investigations/${i.id}`} className="block px-3 py-1 hover:bg-soft">
                <span className="badge mr-2">{i.status}</span>{i.name}
              </Link>
            ))}
            {hits.entities.length > 0 && <div className="p-2 text-mute uppercase">entities</div>}
            {hits.entities.map(e => (
              <Link key={e.id} href={`/investigations/${e.investigation_id}`} className="block px-3 py-1 hover:bg-soft">
                <span className="badge mr-2">{e.type}</span>{e.value}
              </Link>
            ))}
            {hits.findings.length > 0 && <div className="p-2 text-mute uppercase">findings</div>}
            {hits.findings.map(f => (
              <Link key={f.id} href={`/investigations/${f.investigation_id}`} className="block px-3 py-1 hover:bg-soft">
                <span className="badge mr-2">{f.source}</span>{f.kind}
              </Link>
            ))}
          </div>
        )}
      </div>
      <div className="flex items-center gap-4">
        <span className="text-sm font-mono text-ink">{email}</span>
        <button onClick={() => { setToken(null); router.push("/login"); }} className="btn">logout</button>
      </div>
    </header>
  );
}
