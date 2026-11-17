"""Investigation tags."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role, current_user
from ..db import get_session
from ..models import Investigation, AuditLog


router = APIRouter()


class TagIn(BaseModel):
    tags: list[str] = []


@router.get("/{inv_id}")
async def get_tags(inv_id: str, _=Depends(current_user),
                   db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    return {"tags": (inv.tags or {}).get("list") or []}


@router.put("/{inv_id}")
async def set_tags(inv_id: str, data: TagIn,
                   u=Depends(require_role("admin", "analyst")),
                   db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    inv.tags = {"list": sorted(set(data.tags))}
    db.add(AuditLog(user_id=u.id, action="investigation.tags",
                    target=inv_id, detail={"tags": inv.tags["list"]}))
    await db.commit()
    return {"tags": inv.tags["list"]}
