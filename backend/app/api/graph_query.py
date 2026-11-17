"""Graph traversal queries. Given a seed entity (by type+value or id)
and a depth, return the subgraph reachable within `depth` hops.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Entity, Relationship

router = APIRouter()


@router.get("/{inv_id}/traverse")
async def traverse(inv_id: str, type: str | None = None, value: str | None = None,
                   entity_id: str | None = None, depth: int = 2,
                   _: object = Depends(current_user),
                   db: AsyncSession = Depends(get_session)):
    if entity_id:
        seed = await db.get(Entity, entity_id)
    elif type and value:
        q = select(Entity).where(Entity.investigation_id == inv_id,
                                 Entity.type == type, Entity.value == value)
        seed = (await db.execute(q)).scalar_one_or_none()
    else:
        raise HTTPException(400, "pass entity_id or (type,value)")
    if not seed:
        raise HTTPException(404, "seed not found")

    visited = {seed.id}
    frontier = {seed.id}
    rels_out: list[Relationship] = []
    for _ in range(max(0, min(depth, 5))):
        if not frontier:
            break
        q = select(Relationship).where(
            Relationship.investigation_id == inv_id,
            or_(Relationship.src_id.in_(frontier), Relationship.dst_id.in_(frontier)),
        )
        rows = (await db.execute(q)).scalars().all()
        next_frontier: set[str] = set()
        for r in rows:
            if r.src_id not in visited:
                next_frontier.add(r.src_id)
            if r.dst_id not in visited:
                next_frontier.add(r.dst_id)
            rels_out.append(r)
        visited |= next_frontier
        frontier = next_frontier

    ents = (await db.execute(select(Entity).where(Entity.id.in_(visited)))).scalars().all()
    return {
        "seed": {"id": seed.id, "type": seed.type, "value": seed.value},
        "nodes": [{"id": e.id, "type": e.type, "value": e.value,
                   "confidence": e.confidence, "attributes": e.attributes} for e in ents],
        "edges": [{"id": r.id, "src": r.src_id, "dst": r.dst_id, "type": r.type,
                   "source": r.source, "confidence": r.confidence} for r in rels_out],
        "depth": depth,
    }
