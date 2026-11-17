from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Entity, Relationship

router = APIRouter()


@router.get("/{inv_id}")
async def graph(inv_id: str, _: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()
    rels = (await db.execute(select(Relationship).where(Relationship.investigation_id == inv_id))).scalars().all()
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
