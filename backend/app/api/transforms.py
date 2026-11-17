"""Maltego-style transforms.

Expand an existing entity into new intel by promoting it to a subject of the
investigation and running compatible modules against it. Subject-type is
inferred from the entity type (domain->domain, ip->ip, email->email,
username->username, url->url, hash/file->document is skipped).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Entity, Subject, Investigation, AuditLog
from ..queue import enqueue_run
from ..modules import REGISTRY

ENT_TO_SUB = {"domain": "domain", "ip": "ip", "email": "email",
              "username": "username", "url": "url"}

router = APIRouter()


@router.post("/{inv_id}/expand/{entity_id}")
async def expand(inv_id: str, entity_id: str, modules: list[str] | None = None,
                 u=Depends(current_user), db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    ent = await db.get(Entity, entity_id)
    if not inv or not ent or ent.investigation_id != inv_id:
        raise HTTPException(404, "not found")
    stype = ENT_TO_SUB.get(ent.type)
    if not stype:
        raise HTTPException(400, f"entity type '{ent.type}' not expandable")
    # dedupe: reuse an existing subject with the same (type, value)
    existing = (await db.execute(select(Subject).where(
        Subject.investigation_id == inv_id,
        Subject.type == stype, Subject.value == ent.value,
    ))).scalar_one_or_none()
    if existing:
        sub = existing
    else:
        sub = Subject(investigation_id=inv_id, type=stype, value=ent.value,
                      note=f"expanded from {ent.type}:{ent.value}")
        db.add(sub); await db.flush()
    db.add(AuditLog(user_id=u.id, action="transform.expand",
                    target=inv_id, detail={"entity": entity_id, "modules": modules}))
    await db.commit()
    # filter modules to ones that accept this subject type
    if modules:
        modules = [m for m in modules if m in REGISTRY and stype in REGISTRY[m].subject_types]
    await enqueue_run(inv_id, modules, [sub.id])
    return {"subject_id": sub.id, "scheduled": True}
