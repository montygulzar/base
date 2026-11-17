"""Full-text search over findings within one investigation.

A fast case-insensitive substring match against the JSON-stringified
`data` column and the `module` / `source` / `kind` fields. For investigations
over ~100k findings consider adding a dedicated FTS index; this works for
anything up to that size with a single sequential scan.
"""
from __future__ import annotations
import json
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Finding

router = APIRouter()


@router.get("/{inv_id}")
async def search(inv_id: str, q: str, limit: int = 100,
                 _: object = Depends(current_user),
                 db: AsyncSession = Depends(get_session)):
    needle = (q or "").lower()
    if not needle:
        return {"hits": [], "query": q}
    rows = (await db.execute(
        select(Finding).where(Finding.investigation_id == inv_id)
                       .order_by(Finding.collected_at.desc())
    )).scalars().all()
    hits = []
    for f in rows:
        blob = json.dumps(f.data or {}).lower()
        if (needle in blob or needle in f.module.lower()
                or needle in f.source.lower() or needle in f.kind.lower()):
            hits.append({"id": f.id, "module": f.module, "source": f.source,
                         "kind": f.kind, "data": f.data, "confidence": f.confidence,
                         "collected_at": f.collected_at.isoformat()})
            if len(hits) >= limit:
                break
    return {"hits": hits, "count": len(hits), "query": q}
