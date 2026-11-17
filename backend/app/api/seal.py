"""Investigation sealing. Flips the status to 'sealed' and the
`require_role` guards that gate write endpoints then block further
changes. An audit entry records who sealed it.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..db import get_session
from ..models import Investigation, AuditLog

router = APIRouter()


@router.post("/{inv_id}/seal")
async def seal(inv_id: str, u=Depends(require_role("admin")),
               db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    if inv.status == "sealed":
        return {"status": "sealed", "already": True}
    inv.status = "sealed"
    db.add(AuditLog(user_id=u.id, action="investigation.seal", target=inv_id))
    await db.commit()
    return {"status": "sealed"}


@router.post("/{inv_id}/unseal")
async def unseal(inv_id: str, u=Depends(require_role("admin")),
                 db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    if inv.status != "sealed":
        return {"status": inv.status, "noop": True}
    inv.status = "completed"
    db.add(AuditLog(user_id=u.id, action="investigation.unseal", target=inv_id))
    await db.commit()
    return {"status": "completed"}
