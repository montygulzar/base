"use client";
import useSWR from "swr";
import Link from "next/link";
import { fetcher, API_URL } from "@/lib/api";

type Inv = { id: string; name: string; status: string; updated_at: string };

export default function Reports() {
  const { data } = useSWR<Inv[]>("/api/investigations", fetcher);
  return (
    <div className="space-y-4">
      <h1 className="font-mono text-xl">reports</h1>
      <div className="card">
        <table className="w-full text-sm font-mono">
          <thead className="text-mute text-left">
            <tr><th className="p-3">investigation</th><th>status</th><th>exports</th></tr>
          </thead>
          <tbody>
            {(data ?? []).map(i => (
              <tr key={i.id} className="border-t border-line">
                <td className="p-3">
                  <Link className="text-acc" href={`/investigations/${i.id}`}>{i.name}</Link>
                </td>
                <td><span className="badge">{i.status}</span></td>
                <td className="p-3 space-x-2">
                  {["md","html","pdf","csv","json"].map(fmt => (
                    <a key={fmt} className="btn" target="_blank" href={`${API_URL}/api/reports/${i.id}.${fmt}`}>{fmt}</a>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
