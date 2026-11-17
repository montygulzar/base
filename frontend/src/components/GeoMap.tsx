"use client";
import useSWR from "swr";
import { fetcher } from "@/lib/api";

type Feature = { geometry: { coordinates: [number, number] };
                 properties: { source?: string; module?: string; kind?: string; confidence?: number } };
type FC = { features: Feature[] };


function project(lon: number, lat: number, W: number, H: number) {
  // equirectangular
  const x = (lon + 180) * (W / 360);
  const y = (90 - lat) * (H / 180);
  return { x, y };
}


export default function GeoMap({ invId }: { invId: string }) {
  const { data } = useSWR<FC>(`/api/geojson/${invId}.geojson`, fetcher, { refreshInterval: 6000 });
  const feats = data?.features ?? [];
  const W = 720, H = 360;
  return (
    <div className="card p-3">
      <div className="font-mono text-mute text-xs uppercase mb-2">
        locations ({feats.length})
      </div>
      {!feats.length ? (
        <div className="text-mute text-sm font-mono">no geolocated findings yet.</div>
      ) : (
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" className="bg-bg rounded">
          {/* graticule */}
          {[...Array(13)].map((_, i) => (
            <line key={"g" + i} x1={(i * W) / 12} y1={0} x2={(i * W) / 12} y2={H}
                  stroke="#1c212c" strokeWidth="0.5" />
          ))}
          {[...Array(7)].map((_, i) => (
            <line key={"h" + i} x1={0} y1={(i * H) / 6} x2={W} y2={(i * H) / 6}
                  stroke="#1c212c" strokeWidth="0.5" />
          ))}
          <rect x={0} y={0} width={W} height={H} fill="none" stroke="#242b38" />
          {feats.map((f, i) => {
            const [lon, lat] = f.geometry.coordinates;
            const { x, y } = project(lon, lat, W, H);
            return (
              <circle key={i} cx={x} cy={y} r="3" fill="#7dd3fc" opacity="0.8">
                <title>{`${f.properties.source}:${f.properties.kind} @ ${lat.toFixed(2)},${lon.toFixed(2)}`}</title>
              </circle>
            );
          })}
        </svg>
      )}
    </div>
  );
}
