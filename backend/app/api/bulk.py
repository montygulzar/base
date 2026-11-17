"""Bulk operations on entities."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..db import get_session
from ..models import Entity, EntityNote, AuditLog

router = APIRouter()


class BulkIds(BaseModel):
    ids: list[str]


@router.post("/delete")
async def bulk_delete(data: BulkIds, u=Depends(require_role("admin", "analyst")),
                      db: AsyncSession = Depends(get_session)):
    if not data.ids:
        return {"deleted": 0}
    n = (await db.execute(select(Entity.id).where(Entity.id.in_(data.ids)))).scalars().all()
    await db.execute(delete(Entity).where(Entity.id.in_(n)))
    db.add(AuditLog(user_id=u.id, action="entity.bulk_delete",
                    detail={"count": len(n)}))
    await db.commit()
    return {"deleted": len(n)}


class BulkTag(BaseModel):
    ids: list[str]
    tag: str
    note: str = ""


@router.post("/tag")
async def bulk_tag(data: BulkTag, u=Depends(require_role("admin", "analyst")),
                   db: AsyncSession = Depends(get_session)):
    if not data.ids or not data.tag:
        return {"tagged": 0}
    tagged = 0
    for eid in data.ids:
        db.add(EntityNote(entity_id=eid, user_id=u.id,
                          tags={"list": [data.tag]}, note=data.note))
        tagged += 1
    db.add(AuditLog(user_id=u.id, action="entity.bulk_tag",
                    detail={"tag": data.tag, "count": tagged}))
    await db.commit()
    return {"tagged": tagged}
