from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Entity, Relationship

router = APIRouter()


@router.get("/{inv_id}")
async def graph(inv_id: str, min_confidence: float = 0.0, type: str | None = None,
                _: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    q_e = select(Entity).where(Entity.investigation_id == inv_id,
                               Entity.confidence >= min_confidence)
    if type:
        q_e = q_e.where(Entity.type == type)
    ents = (await db.execute(q_e)).scalars().all()
    rels = (await db.execute(
        select(Relationship).where(Relationship.investigation_id == inv_id,
                                   Relationship.confidence >= min_confidence)
    )).scalars().all()
    keep_ids = {e.id for e in ents}
    rels = [r for r in rels if r.src_id in keep_ids and r.dst_id in keep_ids]
    return {
        "nodes": [
            {"id": e.id, "type": e.type, "value": e.value,
             "attributes": e.attributes, "confidence": e.confidence}
            for e in ents
        ],
        "edges": [
            {"id": r.id, "src": r.src_id, "dst": r.dst_id, "type": r.type,
             "source": r.source, "confidence": r.confidence, "evidence": r.evidence}
            for r in rels
        ],
    }
