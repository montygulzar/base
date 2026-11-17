"""Mermaid graph export — paste into any markdown-flavoured doc."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Investigation, Entity, Relationship

router = APIRouter()


def _sanitize(v: str) -> str:
    return (v or "")[:60].replace('"', "'")


@router.get("/{inv_id}.mmd")
async def mermaid(inv_id: str, min_confidence: float = 0.5,
                  _: object = Depends(current_user),
                  db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    ents = (await db.execute(select(Entity).where(
        Entity.investigation_id == inv_id,
        Entity.confidence >= min_confidence))).scalars().all()
    rels = (await db.execute(select(Relationship).where(
        Relationship.investigation_id == inv_id,
        Relationship.confidence >= min_confidence))).scalars().all()
    keep = {e.id: e for e in ents}
    lines = ["graph LR"]
    short = {}
    for i, e in enumerate(keep.values()):
        sid = f"n{i}"
        short[e.id] = sid
        lines.append(f'  {sid}["{e.type}: {_sanitize(e.value)}"]')
    for r in rels:
        if r.src_id in short and r.dst_id in short:
            lines.append(f'  {short[r.src_id]} -->|{_sanitize(r.type)}| {short[r.dst_id]}')
    return Response("\n".join(lines), media_type="text/plain",
                    headers={"content-disposition": f'attachment; filename="{inv_id}.mmd"'})
