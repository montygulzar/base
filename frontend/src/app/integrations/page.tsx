"use client";
import useSWR from "swr";
import { fetcher } from "@/lib/api";

type Integ = {
  name: string; description: string; scope: string[]; docs: string;
  configured: boolean; last_ok_at: string | null; last_error: string;
  rate_limit_remaining: number | null;
};

export default function Integrations() {
  const { data } = useSWR<Integ[]>("/api/integrations", fetcher);
  return (
    <div className="space-y-4">
      <h1 className="font-mono text-xl">sources</h1>
      <div className="grid grid-cols-2 gap-3">
        {(data ?? []).map(i => (
          <div key={i.name} className="card p-4">
            <div className="flex items-center justify-between">
              <div className="font-mono text-ink">{i.name}</div>
              <span className={`badge ${i.configured ? "text-ok border-ok/50" : "text-mute"}`}>
                {i.configured ? "configured" : "unconfigured"}
              </span>
            </div>
            <div className="text-mute text-sm mt-1">{i.description}</div>
            <div className="flex gap-2 mt-2">
              {i.scope?.map(s => <span key={s} className="badge text-xs">{s}</span>)}
            </div>
            {i.last_error && <div className="text-err text-xs mt-2 font-mono">{i.last_error}</div>}
            {i.docs && <a href={i.docs} className="text-acc text-xs mt-2 inline-block" target="_blank">docs →</a>}
          </div>
        ))}
      </div>
      <p className="text-mute text-sm">API keys are set via environment variables; see <code>.env.example</code>.</p>
    </div>
  );
}
