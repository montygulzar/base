"""GeoJSON export — every finding that produced geolocation data becomes
a Point feature, suitable for drop-in map rendering.

Reads lat/lon from any of:
- ipinfo `loc` field ("47.6,-122.3")
- ipapi.co `latitude` / `longitude`
- ip-api.com `lat` / `lon`
- EXIF GPSLatitude / GPSLongitude (from the media module)
- Shodan `location.latitude` / `longitude`
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Investigation, Finding


def _extract_latlon(d: dict) -> tuple[float, float, dict] | None:
    if not isinstance(d, dict):
        return None
    # ipinfo
    loc = d.get("loc")
    if isinstance(loc, str) and "," in loc:
        try:
            lat, lon = (float(x) for x in loc.split(",", 1))
            return lat, lon, {"src": "ipinfo"}
        except Exception:
            pass
    # ipapi.co
    if "latitude" in d and "longitude" in d:
        try:
            return float(d["latitude"]), float(d["longitude"]), {"src": "ipapi"}
        except Exception:
            pass
    # ip-api.com
    if "lat" in d and "lon" in d:
        try:
            return float(d["lat"]), float(d["lon"]), {"src": "ip-api"}
        except Exception:
            pass
    # Shodan
    sh = d.get("location") or {}
    if "latitude" in sh and "longitude" in sh:
        try:
            return float(sh["latitude"]), float(sh["longitude"]), {"src": "shodan"}
        except Exception:
            pass
    # EXIF
    if "GPSLatitude" in d and "GPSLongitude" in d:
        try:
            return float(d["GPSLatitude"]), float(d["GPSLongitude"]), {"src": "exif"}
        except Exception:
            pass
    return None


router = APIRouter()


@router.get("/{inv_id}.geojson")
async def geojson(inv_id: str, _: object = Depends(current_user),
                  db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    finds = (await db.execute(select(Finding).where(Finding.investigation_id == inv_id))).scalars().all()
    features = []
    for f in finds:
        pt = _extract_latlon(f.data)
        if not pt:
            # recurse into nested dicts once
            if isinstance(f.data, dict):
                for v in f.data.values():
                    pt = _extract_latlon(v) if isinstance(v, dict) else None
                    if pt: break
        if not pt:
            continue
        lat, lon, meta = pt
        features.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [lon, lat]},
            "properties": {"source": f.source, "module": f.module, "kind": f.kind,
                           "confidence": f.confidence, "finding_id": f.id, **meta},
        })
    return JSONResponse({"type": "FeatureCollection", "features": features})
