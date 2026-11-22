"""Cascade API — self-propagating investigation endpoint."""
from __future__ import annotations
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user, require_role
from ..db import get_session
from ..models import Investigation, Entity
from ..cascade import run_cascade

router = APIRouter()


class CascadeReq(BaseModel):
    max_hops: int = 3
    min_proximity: float = 0.15
    modules: list[str] | None = None  # override default plan if provided


@router.post("/{inv_id}")
async def cascade(inv_id: str, req: CascadeReq,
                  u = Depends(require_role("admin", "analyst")),
                  db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    # Fire and forget — the orchestrator chain may take minutes.
    asyncio.create_task(run_cascade(inv_id, req.max_hops, req.min_proximity, req.modules, u.id))
    return {"status": "started", "investigation_id": inv_id,
            "max_hops": req.max_hops, "min_proximity": req.min_proximity}


@router.get("/{inv_id}/ranked")
async def ranked(inv_id: str, limit: int = 50, min_proximity: float = 0.05,
                 _: object = Depends(current_user),
                 db: AsyncSession = Depends(get_session)):
    """Entities sorted by their proximity back to the original seed(s).

    After a cascade run, this is the 'strongest-linked discoveries'
    view — the entities most likely to actually be connected to the
    target, not just surface noise.
    """
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    ents = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id))).scalars().all()
    rows = []
    for e in ents:
        a = e.attributes or {}
        p = a.get("root_proximity")
        if p is None or p < min_proximity:
            continue
        rows.append({
            "id": e.id, "type": e.type, "value": e.value,
            "hop": a.get("hop"),
            "root_proximity": p,
            "is_root": bool(a.get("is_root")),
            "confidence": e.confidence,
        })
    rows.sort(key=lambda r: (-(r["root_proximity"] or 0), r["hop"] or 999))
    return rows[: max(1, min(limit, 500))]
