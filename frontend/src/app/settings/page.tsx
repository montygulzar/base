"use client";
import useSWR from "swr";
import { fetcher } from "@/lib/api";

type C = { flags: Record<string, any>; secrets_present: Record<string, boolean> };

export default function Settings() {
  const { data, error } = useSWR<C>("/api/config", fetcher);
  if (error) return <div className="text-err font-mono">admin only — {error.message}</div>;
  return (
    <div className="space-y-4">
      <h1 className="font-mono text-xl">settings</h1>
      <div className="grid grid-cols-2 gap-4">
        <div className="card p-4">
          <div className="font-mono text-mute text-xs uppercase mb-2">runtime flags</div>
          <table className="text-sm font-mono w-full">
            <tbody>
              {Object.entries(data?.flags ?? {}).map(([k, v]) => (
                <tr key={k} className="border-t border-line">
                  <td className="py-1 text-mute pr-4">{k}</td>
                  <td className="py-1">{String(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card p-4">
          <div className="font-mono text-mute text-xs uppercase mb-2">api keys (set via .env, never shown here)</div>
          <table className="text-sm font-mono w-full">
            <tbody>
              {Object.entries(data?.secrets_present ?? {}).map(([k, v]) => (
                <tr key={k} className="border-t border-line">
                  <td className="py-1 text-mute pr-4">{k}</td>
                  <td className="py-1">{v ? <span className="text-ok">configured</span> : <span className="text-mute">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div className="text-mute text-xs font-mono">
        Set secrets by editing <code>.env</code> and restarting the backend. Values are never served by the API.
      </div>
    </div>
  );
}
