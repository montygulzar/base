"""Auto-enrichment. Walks the investigation's current graph and promotes
every domain/ip/email/username entity that has NO prior subject record to
a new subject, then runs the default plan on each.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..db import get_session
from ..models import Investigation, Entity, Subject, AuditLog
from ..queue import enqueue_run

router = APIRouter()
ELIGIBLE = {"domain", "ip", "email", "username", "url"}


@router.post("/{inv_id}")
async def enrich(inv_id: str, u=Depends(require_role("admin", "analyst")),
                 db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    subs = (await db.execute(select(Subject).where(Subject.investigation_id == inv_id))).scalars().all()
    existing = {(s.type, s.value) for s in subs}
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()

    new_subject_ids: list[str] = []
    for e in ents:
        if e.type not in ELIGIBLE:
            continue
        if (e.type, e.value) in existing:
            continue
        s = Subject(investigation_id=inv_id, type=e.type, value=e.value,
                    note=f"auto-enriched from entity {e.id}")
        db.add(s); await db.flush()
        new_subject_ids.append(s.id)

    db.add(AuditLog(user_id=u.id, action="investigation.enrich", target=inv_id,
                    detail={"new_subjects": len(new_subject_ids)}))
    await db.commit()
    if new_subject_ids:
        await enqueue_run(inv_id, None, new_subject_ids)
    return {"new_subjects": len(new_subject_ids), "scheduled": bool(new_subject_ids)}
