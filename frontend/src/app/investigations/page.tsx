"use client";
import useSWR from "swr";
import { useState } from "react";
import { api, fetcher } from "@/lib/api";
import Link from "next/link";

type Inv = { id: string; name: string; status: string; updated_at: string };

const SUBJECT_TYPES = ["domain", "ip", "email", "username", "company", "url", "document", "media"] as const;

export default function Investigations() {
  const { data, mutate } = useSWR<Inv[]>("/api/investigations", fetcher);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDesc] = useState("");
  const [subjects, setSubjects] = useState<{ type: string; value: string; note: string }[]>([
    { type: "domain", value: "", note: "" },
  ]);

  async function create() {
    await api("/api/investigations", {
      method: "POST",
      body: JSON.stringify({ name, description, subjects: subjects.filter(s => s.value) }),
    });
    setOpen(false); setName(""); setDesc(""); setSubjects([{ type: "domain", value: "", note: "" }]);
    mutate();
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="font-mono text-xl">investigations</h1>
        <button className="btn-primary" onClick={() => setOpen(true)}>new investigation</button>
      </div>
      <div className="card">
        <table className="w-full text-sm font-mono">
          <thead className="text-mute text-left">
            <tr><th className="p-3">name</th><th>status</th><th>updated</th><th></th></tr>
          </thead>
          <tbody>
            {(data ?? []).map(i => (
              <tr key={i.id} className="border-t border-line">
                <td className="p-3">{i.name}</td>
                <td><span className="badge">{i.status}</span></td>
                <td className="text-mute">{new Date(i.updated_at).toLocaleString()}</td>
                <td className="p-3"><Link className="text-acc" href={`/investigations/${i.id}`}>open →</Link></td>
              </tr>
            ))}
            {(data ?? []).length === 0 && <tr><td colSpan={4} className="text-mute p-6">none yet</td></tr>}
          </tbody>
        </table>
      </div>

      {open && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="card w-[560px] p-5 space-y-3">
            <div className="font-mono text-mute uppercase text-xs">new investigation</div>
            <input className="input w-full" placeholder="name" value={name} onChange={e => setName(e.target.value)} />
            <textarea className="input w-full h-20" placeholder="description" value={description} onChange={e => setDesc(e.target.value)} />
            <div className="font-mono text-mute text-xs uppercase">subjects</div>
            {subjects.map((s, i) => (
              <div key={i} className="flex gap-2">
                <select className="input" value={s.type} onChange={e => {
                  const c = [...subjects]; c[i].type = e.target.value; setSubjects(c);
                }}>
                  {SUBJECT_TYPES.map(t => <option key={t}>{t}</option>)}
                </select>
                <input className="input flex-1" placeholder="value" value={s.value}
                       onChange={e => { const c = [...subjects]; c[i].value = e.target.value; setSubjects(c); }} />
                <input className="input flex-1" placeholder="note" value={s.note}
                       onChange={e => { const c = [...subjects]; c[i].note = e.target.value; setSubjects(c); }} />
              </div>
            ))}
            <button className="btn" onClick={() => setSubjects([...subjects, { type: "domain", value: "", note: "" }])}>+ add subject</button>
            <div className="flex justify-end gap-2 pt-2">
              <button className="btn" onClick={() => setOpen(false)}>cancel</button>
              <button className="btn-primary" onClick={create} disabled={!name}>create</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
