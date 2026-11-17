"use client";
import useSWR from "swr";
import { useState } from "react";
import { api, fetcher } from "@/lib/api";

type Tmpl = { id: string; name: string; description: string;
              modules: Record<string, string[]>; created_at: string };

const SUBJECT_TYPES = ["domain", "ip", "email", "username", "company", "url", "phone"];

export default function Templates() {
  const { data, mutate } = useSWR<Tmpl[]>("/api/templates", fetcher);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDesc] = useState("");
  const [modules, setModules] = useState<Record<string, string>>({});

  async function create() {
    const parsed: Record<string, string[]> = {};
    for (const [k, v] of Object.entries(modules))
      if (v) parsed[k] = v.split(",").map(s => s.trim()).filter(Boolean);
    await api("/api/templates", { method: "POST",
      body: JSON.stringify({ name, description, modules: parsed }) });
    setOpen(false); setName(""); setDesc(""); setModules({}); mutate();
  }
  async function del(id: string) { await api(`/api/templates/${id}`, { method: "DELETE" }); mutate(); }

  return (
    <div className="space-y-4">
      <div className="flex justify-between">
        <h1 className="font-mono text-xl">templates</h1>
        <button className="btn-primary" onClick={() => setOpen(true)}>new template</button>
      </div>
      <div className="card">
        <table className="w-full text-sm font-mono">
          <thead className="text-mute text-left">
            <tr><th className="p-3">name</th><th>subjects → modules</th><th></th></tr>
          </thead>
          <tbody>
            {(data ?? []).map(t => (
              <tr key={t.id} className="border-t border-line align-top">
                <td className="p-3">{t.name}</td>
                <td className="p-3">
                  {Object.entries(t.modules || {}).map(([k, v]) => (
                    <div key={k}><span className="badge mr-1">{k}</span>{(v as string[]).join(", ")}</div>
                  ))}
                </td>
                <td className="p-3"><button className="btn" onClick={() => del(t.id)}>delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {open && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="card w-[640px] p-5 space-y-3">
            <div className="font-mono text-mute uppercase text-xs">new template</div>
            <input className="input w-full" placeholder="name" value={name} onChange={e => setName(e.target.value)} />
            <textarea className="input w-full h-16" placeholder="description" value={description} onChange={e => setDesc(e.target.value)} />
            <div className="font-mono text-mute text-xs uppercase">subject → modules (comma separated)</div>
            {SUBJECT_TYPES.map(t => (
              <div key={t} className="flex gap-2">
                <span className="badge w-24">{t}</span>
                <input className="input flex-1" placeholder="module1, module2, …" value={modules[t] ?? ""}
                       onChange={e => setModules({ ...modules, [t]: e.target.value })} />
              </div>
            ))}
            <div className="flex justify-end gap-2">
              <button className="btn" onClick={() => setOpen(false)}>cancel</button>
              <button className="btn-primary" onClick={create} disabled={!name}>create</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
