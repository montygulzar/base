"""Investigation diff — compares two investigations' entity sets."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Investigation, Entity

router = APIRouter()


@router.get("/{a_id}/vs/{b_id}")
async def diff(a_id: str, b_id: str, _: object = Depends(current_user),
               db: AsyncSession = Depends(get_session)):
    if a_id == b_id:
        raise HTTPException(400, "same investigation")
    a_inv = await db.get(Investigation, a_id)
    b_inv = await db.get(Investigation, b_id)
    if not a_inv or not b_inv:
        raise HTTPException(404, "not found")
    a_ents = (await db.execute(select(Entity).where(Entity.investigation_id == a_id))).scalars().all()
    b_ents = (await db.execute(select(Entity).where(Entity.investigation_id == b_id))).scalars().all()
    a_set = {(e.type, e.value) for e in a_ents}
    b_set = {(e.type, e.value) for e in b_ents}
    shared = sorted(a_set & b_set)
    only_a = sorted(a_set - b_set)
    only_b = sorted(b_set - a_set)
    return {
        "a": {"id": a_id, "name": a_inv.name, "entity_count": len(a_set)},
        "b": {"id": b_id, "name": b_inv.name, "entity_count": len(b_set)},
        "shared": [{"type": t, "value": v} for t, v in shared],
        "only_a": [{"type": t, "value": v} for t, v in only_a],
        "only_b": [{"type": t, "value": v} for t, v in only_b],
        "overlap_count": len(shared),
    }
