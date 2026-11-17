"""Per-user API keys for CLI / automation.

Usage: once issued, pass `X-API-Key: <key>` on API requests instead of
the normal Bearer JWT. The middleware in `auth.py` is unchanged — this
is a separate `current_user_via_key` dependency; endpoints that want
API-key-friendliness can opt in by declaring it.
"""
from __future__ import annotations
import hashlib
import secrets
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user, require_role
from ..db import get_session
from ..models import ApiKey, User, AuditLog

router = APIRouter()


def _h(k: str) -> str:
    return hashlib.sha256(k.encode()).hexdigest()


class KeyIn(BaseModel):
    label: str = ""


@router.post("")
async def issue(data: KeyIn, u=Depends(require_role("admin", "analyst")),
                db: AsyncSession = Depends(get_session)):
    raw = "base_" + secrets.token_urlsafe(32)
    row = ApiKey(user_id=u.id, label=data.label, hash=_h(raw))
    db.add(row); await db.commit(); await db.refresh(row)
    db.add(AuditLog(user_id=u.id, action="apikey.issue", target=row.id,
                    detail={"label": data.label}))
    await db.commit()
    return {"id": row.id, "label": row.label, "key": raw,
            "warning": "this is the only time the full key is shown"}


@router.get("")
async def list_keys(u=Depends(current_user), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(ApiKey).where(ApiKey.user_id == u.id))).scalars().all()
    return [{"id": r.id, "label": r.label,
             "created_at": r.created_at.isoformat(),
             "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None} for r in rows]


@router.delete("/{kid}")
async def revoke(kid: str, u=Depends(current_user), db: AsyncSession = Depends(get_session)):
    row = await db.get(ApiKey, kid)
    if not row or row.user_id != u.id:
        raise HTTPException(404, "not found")
    await db.delete(row)
    db.add(AuditLog(user_id=u.id, action="apikey.revoke", target=kid))
    await db.commit()
    return {"deleted": kid}
