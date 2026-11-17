"""User management (admin only)."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role, hash_password
from ..db import get_session
from ..models import User, AuditLog

router = APIRouter()


class UserPatch(BaseModel):
    role: str | None = None
    password: str | None = None


@router.get("")
async def list_users(_=Depends(require_role("admin")), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(User))).scalars().all()
    return [{"id": u.id, "email": u.email, "role": u.role,
             "created_at": u.created_at.isoformat()} for u in rows]


@router.patch("/{uid}")
async def patch(uid: str, data: UserPatch, u=Depends(require_role("admin")),
                db: AsyncSession = Depends(get_session)):
    row = await db.get(User, uid)
    if not row:
        raise HTTPException(404, "not found")
    changes = {}
    if data.role and data.role in ("admin", "analyst", "viewer"):
        row.role = data.role
        changes["role"] = data.role
    if data.password:
        row.password_hash = hash_password(data.password)
        changes["password"] = "changed"
    db.add(AuditLog(user_id=u.id, action="user.update", target=uid, detail=changes))
    await db.commit()
    return {"id": uid, "role": row.role}


@router.delete("/{uid}")
async def delete(uid: str, u=Depends(require_role("admin")),
                 db: AsyncSession = Depends(get_session)):
    row = await db.get(User, uid)
    if not row:
        raise HTTPException(404, "not found")
    if row.id == u.id:
        raise HTTPException(400, "cannot delete self")
    await db.delete(row)
    db.add(AuditLog(user_id=u.id, action="user.delete", target=uid))
    await db.commit()
    return {"deleted": uid}
