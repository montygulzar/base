"""Recent findings feed (newest N across all investigations)."""
from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Finding

router = APIRouter()


@router.get("")
async def recent(limit: int = 30, _: object = Depends(current_user),
                 db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(
        select(Finding).order_by(Finding.collected_at.desc()).limit(min(limit, 200))
    )).scalars().all()
    out = []
    for f in rows:
        d = f.data or {}
        # ship a trimmed data view so the Dramatist can classify without
        # dragging multi-megabyte crawler blobs across the wire.
        preview = {k: d[k] for k in (
            "count", "hits", "hit", "query_status", "total_hits",
            "verdict", "candidates", "urls", "onions_found",
            "total_unique", "live", "hit_count",
        ) if k in d}
        # keep nested abuseipdb shape
        if isinstance(d.get("data"), dict) and "abuseConfidenceScore" in d["data"]:
            preview["data"] = {"abuseConfidenceScore": d["data"]["abuseConfidenceScore"]}
        out.append({
            "id": f.id, "investigation_id": f.investigation_id,
            "module": f.module, "source": f.source, "kind": f.kind,
            "confidence": f.confidence,
            "collected_at": f.collected_at.isoformat(),
            "data": preview,
        })
    return out
