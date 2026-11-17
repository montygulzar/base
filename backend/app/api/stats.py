"""Per-investigation stats for dashboards."""
from __future__ import annotations
from collections import Counter
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Entity, Finding, Job, Investigation


router = APIRouter()


@router.get("/global")
async def global_stats(_: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    inv_count = (await db.execute(select(func.count(Investigation.id)))).scalar() or 0
    ent_count = (await db.execute(select(func.count(Entity.id)))).scalar() or 0
    find_count = (await db.execute(select(func.count(Finding.id)))).scalar() or 0
    # entity type histogram across all investigations
    rows = (await db.execute(select(Entity.type))).scalars().all()
    hist = Counter(rows)
    return {"investigations": inv_count, "entities": ent_count,
            "findings": find_count, "entity_types": dict(hist)}


@router.get("/{inv_id}")
async def inv_stats(inv_id: str, _: object = Depends(current_user),
                    db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()
    finds = (await db.execute(select(Finding).where(Finding.investigation_id == inv_id))).scalars().all()
    jobs = (await db.execute(select(Job).where(Job.investigation_id == inv_id))).scalars().all()
    return {
        "investigation": {"id": inv.id, "name": inv.name, "status": inv.status},
        "entities": len(ents),
        "entities_by_type": dict(Counter(e.type for e in ents).most_common()),
        "findings": len(finds),
        "findings_by_module": dict(Counter(f.module for f in finds).most_common()),
        "findings_by_source": dict(Counter(f.source for f in finds).most_common()),
        "jobs": len(jobs),
        "jobs_by_status": dict(Counter(j.status for j in jobs).most_common()),
    }
