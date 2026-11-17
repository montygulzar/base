"""Global entity + finding search across every investigation.

Case-insensitive substring match on entity.value and finding.data.
"""
from __future__ import annotations
import json
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Entity, Finding, Investigation

router = APIRouter()


@router.get("")
async def global_search(q: str, limit: int = 100,
                        _: object = Depends(current_user),
                        db: AsyncSession = Depends(get_session)):
    needle = (q or "").strip().lower()
    if not needle:
        return {"entities": [], "findings": [], "investigations": []}
    inv_rows = (await db.execute(select(Investigation))).scalars().all()
    inv_hits = [{"id": i.id, "name": i.name, "status": i.status}
                for i in inv_rows if needle in i.name.lower()
                or needle in (i.description or "").lower()][:limit]

    e_rows = (await db.execute(select(Entity))).scalars().all()
    e_hits = []
    for e in e_rows:
        if needle in e.value.lower():
            e_hits.append({"id": e.id, "type": e.type, "value": e.value,
                            "investigation_id": e.investigation_id,
                            "confidence": e.confidence})
            if len(e_hits) >= limit:
                break

    f_hits = []
    f_rows = (await db.execute(select(Finding).order_by(Finding.collected_at.desc()))).scalars().all()
    for f in f_rows:
        blob = json.dumps(f.data or {}).lower()
        if (needle in blob or needle in f.module.lower()
                or needle in f.source.lower() or needle in f.kind.lower()):
            f_hits.append({"id": f.id, "module": f.module, "source": f.source,
                           "kind": f.kind, "confidence": f.confidence,
                           "investigation_id": f.investigation_id,
                           "collected_at": f.collected_at.isoformat()})
            if len(f_hits) >= limit:
                break

    return {"investigations": inv_hits, "entities": e_hits, "findings": f_hits,
            "query": needle}
