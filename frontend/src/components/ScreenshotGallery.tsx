"use client";
import useSWR from "swr";
import { API_URL, fetcher, getToken } from "@/lib/api";

type S = { screenshots: { name: string; bytes: number; download_url: string }[] };

export default function ScreenshotGallery({ invId }: { invId: string }) {
  const { data } = useSWR<S>(`/api/screenshots/${invId}`, fetcher, { refreshInterval: 6000 });
  const shots = data?.screenshots ?? [];
  const tok = getToken();
  return (
    <div className="card p-3">
      <div className="font-mono text-mute text-xs uppercase mb-2">
        screenshots ({shots.length})
      </div>
      {!shots.length ? (
        <div className="text-mute text-sm font-mono">none yet — run the screenshot module.</div>
      ) : (
        <div className="grid grid-cols-3 gap-2">
          {shots.map(s => (
            <a key={s.name} target="_blank"
               href={`${API_URL}${s.download_url}?t=${encodeURIComponent(tok ?? "")}`}
               className="block border border-line rounded overflow-hidden hover:border-acc">
              <img src={`${API_URL}${s.download_url}?t=${encodeURIComponent(tok ?? "")}`}
                   alt={s.name} className="w-full aspect-video object-cover bg-bg" />
              <div className="px-2 py-1 text-xs font-mono text-mute truncate">{s.name}</div>
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
