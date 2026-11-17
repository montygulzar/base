"""Audit log viewer (admin only)."""
from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..db import get_session
from ..models import AuditLog

router = APIRouter()


@router.get("")
async def recent(limit: int = 200, _: object = Depends(require_role("admin")),
                 db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(
        select(AuditLog).order_by(AuditLog.at.desc()).limit(min(limit, 1000))
    )).scalars().all()
    return [{"id": r.id, "user_id": r.user_id, "action": r.action,
             "target": r.target, "detail": r.detail, "at": r.at.isoformat()} for r in rows]
