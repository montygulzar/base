"use client";
import { useEffect, useRef, useState } from "react";
import { fetcher, api } from "@/lib/api";
import useSWR from "swr";
import { classify, pickQuip, cascadeQuip, Quip } from "@/lib/quips";

type Toast = { id: number; text: string; severity: Quip["severity"]; ctx?: string };
type Finding = { id: string; module: string; source: string; kind: string; data: any; investigation_id: string; collected_at: string };

// Global mount: watches /api/recent + newly-promoted cascade entities and
// pops a toast when something juicy lands. Never duplicates.
export default function Dramatist() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const seenFindings = useRef<Set<string>>(new Set());
  const seenEntities = useRef<Set<string>>(new Set());
  const nextId = useRef(1);

  const pushToast = (q: Quip | null, ctx?: string) => {
    if (!q) return;
    const id = nextId.current++;
    setToasts(prev => [...prev, { id, text: q.text, severity: q.severity, ctx }]);
    const ttl = q.severity === "oh_no" ? 9000 : q.severity === "loud" ? 7000 : 5000;
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), ttl);
  };

  // poll recent findings
  const recent = useSWR<Finding[]>("/api/recent?limit=40", fetcher, { refreshInterval: 4000 });
  useEffect(() => {
    if (!recent.data) return;
    // reverse so oldest first — we want them to land in order
    const unseen = recent.data.filter(f => !seenFindings.current.has(f.id));
    // warm start: on first load we just mark everything seen, no spam
    if (seenFindings.current.size === 0 && recent.data.length > 0) {
      recent.data.forEach(f => seenFindings.current.add(f.id));
      return;
    }
    for (const f of unseen.reverse()) {
      seenFindings.current.add(f.id);
      const c = classify(f);
      if (c) {
        const q = pickQuip(c.key, c.vars);
        pushToast(q, `${f.source} · ${f.kind}`);
      }
    }
  }, [recent.data]);

  // poll cascade-ranked across all investigations lazily — only when
  // the user is on an investigation page to avoid a global N+1.
  // Simpler approach: subscribe to /api/stats/global shifts — skip for now.

  return (
    <div className="fixed bottom-4 right-4 z-[99999] flex flex-col gap-2 w-[360px] pointer-events-none">
      {toasts.map(t => <ToastCard key={t.id} toast={t} onClose={() =>
        setToasts(prev => prev.filter(x => x.id !== t.id))} />)}
    </div>
  );
}

function ToastCard({ toast, onClose }: { toast: Toast; onClose: () => void }) {
  const color = toast.severity === "oh_no" ? "border-acc text-ink"
              : toast.severity === "loud"  ? "border-acc/60 text-ink"
              : "border-line text-ink";
  const bar = toast.severity === "oh_no" ? "bg-acc"
            : toast.severity === "loud"  ? "bg-acc/70"
            : "bg-mute/40";
  return (
    <div className={`card pointer-events-auto border-l-2 ${color} shadow-xl animate-[fadein_.18s]`}>
      <div className="flex items-stretch">
        <div className={`w-0.5 ${bar}`} />
        <div className="px-3 py-2 flex-1">
          <div className="text-[13px] leading-snug">{toast.text}</div>
          {toast.ctx && <div className="text-[10px] text-dim mt-0.5">{toast.ctx}</div>}
        </div>
        <button className="px-2 text-dim hover:text-ink text-sm" onClick={onClose}>×</button>
      </div>
    </div>
  );
}
