"""Merge two entities: keep `keep_id`, migrate every relationship from
`dupe_id` to point at `keep_id`, carry over notes, delete the duplicate.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..db import get_session
from ..models import Entity, Relationship, EntityNote, AuditLog, Finding

router = APIRouter()


class MergeIn(BaseModel):
    keep_id: str
    dupe_id: str


@router.post("")
async def merge(data: MergeIn, u=Depends(require_role("admin", "analyst")),
                db: AsyncSession = Depends(get_session)):
    if data.keep_id == data.dupe_id:
        raise HTTPException(400, "cannot merge entity with itself")
    keep = await db.get(Entity, data.keep_id)
    dupe = await db.get(Entity, data.dupe_id)
    if not keep or not dupe:
        raise HTTPException(404, "entity not found")
    if keep.investigation_id != dupe.investigation_id:
        raise HTTPException(400, "entities belong to different investigations")
    # merge attributes (prefer keep's values on conflict)
    merged_attrs = {**(dupe.attributes or {}), **(keep.attributes or {})}
    keep.attributes = merged_attrs
    keep.confidence = max(keep.confidence, dupe.confidence)
    # rewrite relationships
    await db.execute(update(Relationship).where(Relationship.src_id == dupe.id).values(src_id=keep.id))
    await db.execute(update(Relationship).where(Relationship.dst_id == dupe.id).values(dst_id=keep.id))
    # migrate findings + notes pointer
    await db.execute(update(Finding).where(Finding.entity_id == dupe.id).values(entity_id=keep.id))
    await db.execute(update(EntityNote).where(EntityNote.entity_id == dupe.id).values(entity_id=keep.id))
    # drop any self-loops just created
    await db.execute(delete(Relationship).where(Relationship.src_id == Relationship.dst_id))
    await db.delete(dupe)
    db.add(AuditLog(user_id=u.id, action="entity.merge", target=keep.id,
                    detail={"dupe": data.dupe_id,
                            "merged_value": dupe.value,
                            "merged_type": dupe.type}))
    await db.commit()
    return {"keep_id": keep.id, "deleted": dupe.id}
