"use client";
import useSWR from "swr";
import { useState } from "react";
import { fetcher } from "@/lib/api";

type M = { key: string; name: string; description: string; subject_types: string[] };

export default function Modules() {
  const { data } = useSWR<M[]>("/api/modules", fetcher);
  const [q, setQ] = useState("");
  const [subject, setSubject] = useState<string>("");
  const mods = data ?? [];
  const needle = q.trim().toLowerCase();
  const filtered = mods.filter(m =>
    (!needle || m.key.includes(needle) || m.name.toLowerCase().includes(needle)
      || m.description.toLowerCase().includes(needle))
    && (!subject || m.subject_types.includes(subject))
  );
  const allSubjects = Array.from(new Set(mods.flatMap(m => m.subject_types))).sort();
  return (
    <div className="space-y-4">
      <h1 className="font-mono text-xl">modules ({mods.length})</h1>
      <div className="flex gap-2">
        <input className="input flex-1" placeholder="search modules…" value={q} onChange={e => setQ(e.target.value)} />
        <select className="input" value={subject} onChange={e => setSubject(e.target.value)}>
          <option value="">all subject types</option>
          {allSubjects.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      <div className="grid grid-cols-2 gap-3">
        {filtered.map(m => (
          <div key={m.key} className="card p-3">
            <div className="flex items-center justify-between">
              <div className="font-mono text-acc">{m.key}</div>
              <div className="flex gap-1">
                {m.subject_types.slice(0, 5).map(s => <span key={s} className="badge">{s}</span>)}
              </div>
            </div>
            <div className="font-mono text-ink mt-1">{m.name}</div>
            <div className="text-mute text-sm mt-1">{m.description}</div>
          </div>
        ))}
        {!filtered.length && <div className="text-mute font-mono">no matches</div>}
      </div>
    </div>
  );
}
