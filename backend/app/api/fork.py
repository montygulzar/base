"""Fork an investigation — copy subjects / entities / relationships /
findings into a new investigation record. Jobs are not copied (fresh
state).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..db import get_session
from ..models import Investigation, Subject, Entity, Relationship, Finding, AuditLog

router = APIRouter()


class ForkReq(BaseModel):
    name: str
    description: str = ""
    include_findings: bool = True


@router.post("/{inv_id}")
async def fork(inv_id: str, req: ForkReq, u=Depends(require_role("admin", "analyst")),
               db: AsyncSession = Depends(get_session)):
    src = await db.get(Investigation, inv_id)
    if not src:
        raise HTTPException(404, "source not found")
    new = Investigation(name=req.name, description=req.description or f"fork of {src.name}",
                         owner_id=u.id)
    db.add(new); await db.flush()
    for s in (await db.execute(select(Subject).where(Subject.investigation_id == inv_id))).scalars().all():
        db.add(Subject(investigation_id=new.id, type=s.type, value=s.value, note=f"from {inv_id[:8]}"))
    # entity id map so we can rebuild relationships
    emap: dict[str, str] = {}
    for e in (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all():
        ne = Entity(investigation_id=new.id, type=e.type, value=e.value,
                    attributes=dict(e.attributes or {}), confidence=e.confidence)
        db.add(ne); await db.flush()
        emap[e.id] = ne.id
    for r in (await db.execute(select(Relationship).where(Relationship.investigation_id == inv_id))).scalars().all():
        sid, did = emap.get(r.src_id), emap.get(r.dst_id)
        if sid and did:
            db.add(Relationship(investigation_id=new.id, src_id=sid, dst_id=did,
                                type=r.type, source=r.source, confidence=r.confidence,
                                evidence=dict(r.evidence or {})))
    if req.include_findings:
        for f in (await db.execute(select(Finding).where(Finding.investigation_id == inv_id))).scalars().all():
            db.add(Finding(investigation_id=new.id, job_id=None,
                           entity_id=emap.get(f.entity_id) if f.entity_id else None,
                           module=f.module, source=f.source, kind=f.kind,
                           data=dict(f.data or {}), confidence=f.confidence))
    db.add(AuditLog(user_id=u.id, action="investigation.fork", target=new.id,
                    detail={"source": inv_id, "include_findings": req.include_findings}))
    await db.commit()
    return {"id": new.id, "entities_copied": len(emap)}
