"use client";
import useSWR from "swr";
import { useState } from "react";
import { api, fetcher } from "@/lib/api";

type M = { key: string; name: string; description: string; subject_types: string[] };

export default function Scratchpad() {
  const { data: mods } = useSWR<M[]>("/api/modules", fetcher);
  const [mod, setMod] = useState("");
  const [subject, setSubject] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  async function go() {
    if (!mod || !subject) return;
    setBusy(true);
    try {
      setResult(await api("/api/scratchpad", { method: "POST",
        body: JSON.stringify({ module: mod, subject }) }));
    } catch (e) { setResult({ error: String(e) }); }
    finally { setBusy(false); }
  }
  return (
    <div className="space-y-4">
      <h1 className="font-mono text-xl">scratchpad</h1>
      <div className="text-mute text-sm">Fire one module at one value. Nothing is persisted.</div>
      <div className="card p-3 flex gap-2 items-center">
        <select className="input" value={mod} onChange={e => setMod(e.target.value)}>
          <option value="">— module —</option>
          {(mods ?? []).sort((a, b) => a.key.localeCompare(b.key)).map(m => (
            <option key={m.key} value={m.key}>{m.key}</option>
          ))}
        </select>
        <input className="input flex-1" placeholder="subject value" value={subject}
               onChange={e => setSubject(e.target.value)}
               onKeyDown={e => e.key === "Enter" && go()} />
        <button className="btn-primary" onClick={go} disabled={!mod || !subject || busy}>
          {busy ? "running…" : "run"}
        </button>
      </div>
      {result && (
        <div className="card p-3">
          <div className="font-mono text-mute text-xs uppercase mb-2">result</div>
          <pre className="text-xs whitespace-pre-wrap overflow-auto max-h-[70vh]">{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
