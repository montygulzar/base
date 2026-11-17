"""Combine multiple investigations into one graph view.

POST with a list of investigation ids returns the merged node/edge set.
Entities with the same (type, value) across investigations are collapsed
into one node (confidence = max), and the `investigations` attribute
lists which investigations contained it.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Entity, Relationship

router = APIRouter()


class CombineIn(BaseModel):
    investigation_ids: list[str]
    min_confidence: float = 0.0


@router.post("")
async def combine(data: CombineIn, _: object = Depends(current_user),
                  db: AsyncSession = Depends(get_session)):
    if not data.investigation_ids:
        return {"nodes": [], "edges": []}
    ents = (await db.execute(
        select(Entity).where(Entity.investigation_id.in_(data.investigation_ids),
                             Entity.confidence >= data.min_confidence))).scalars().all()
    # dedupe nodes by (type, value)
    node_key = {}
    nodes = {}
    for e in ents:
        k = (e.type, e.value)
        if k not in nodes:
            nid = f"cm_{len(nodes)}"
            nodes[k] = {"id": nid, "type": e.type, "value": e.value,
                        "confidence": e.confidence, "attributes": dict(e.attributes or {}),
                        "investigations": [e.investigation_id],
                        "entity_ids": [e.id]}
        else:
            n = nodes[k]
            n["confidence"] = max(n["confidence"], e.confidence)
            if e.investigation_id not in n["investigations"]:
                n["investigations"].append(e.investigation_id)
            n["entity_ids"].append(e.id)
        node_key[e.id] = nodes[k]["id"]
    rels = (await db.execute(
        select(Relationship).where(Relationship.investigation_id.in_(data.investigation_ids),
                                    Relationship.confidence >= data.min_confidence))).scalars().all()
    edges = []
    seen_edges: set[tuple[str, str, str]] = set()
    for r in rels:
        s, d = node_key.get(r.src_id), node_key.get(r.dst_id)
        if not s or not d:
            continue
        key = (s, d, r.type)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        edges.append({"id": f"e_{len(edges)}", "src": s, "dst": d, "type": r.type,
                      "source": r.source, "confidence": r.confidence})
    return {"nodes": list(nodes.values()), "edges": edges,
            "investigation_count": len(data.investigation_ids)}
