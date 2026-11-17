"""Graph-degree ranking — which entities are most-connected.

Returns nodes sorted by (in + out) with per-entity breakdown.
"""
from __future__ import annotations
from collections import Counter
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Entity, Relationship

router = APIRouter()


@router.get("/{inv_id}")
async def degrees(inv_id: str, limit: int = 50,
                  _: object = Depends(current_user),
                  db: AsyncSession = Depends(get_session)):
    rels = (await db.execute(select(Relationship).where(Relationship.investigation_id == inv_id))).scalars().all()
    in_deg: Counter[str] = Counter()
    out_deg: Counter[str] = Counter()
    for r in rels:
        out_deg[r.src_id] += 1
        in_deg[r.dst_id] += 1
    all_ids = set(in_deg) | set(out_deg)
    ents = {e.id: e for e in (await db.execute(
        select(Entity).where(Entity.id.in_(all_ids)))).scalars().all()}
    rows = [{
        "id": eid, "type": ents[eid].type if eid in ents else "?",
        "value": ents[eid].value if eid in ents else "?",
        "in_degree": in_deg.get(eid, 0),
        "out_degree": out_deg.get(eid, 0),
        "degree": in_deg.get(eid, 0) + out_deg.get(eid, 0),
    } for eid in all_ids]
    rows.sort(key=lambda r: r["degree"], reverse=True)
    return rows[: min(limit, 500)]
