"""Retention — purge old / errored jobs + findings older than N days.

Admin-only. Does NOT delete investigations themselves — those come off
via /api/investigations/{id} DELETE.
"""
from __future__ import annotations
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import delete, select, func
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..db import get_session
from ..models import Finding, Job, AuditLog

router = APIRouter()


class PurgeIn(BaseModel):
    older_than_days: int = 90
    dry_run: bool = True


@router.post("")
async def purge(data: PurgeIn, u=Depends(require_role("admin")),
                db: AsyncSession = Depends(get_session)):
    cutoff = datetime.utcnow() - timedelta(days=max(1, data.older_than_days))
    find_count = (await db.execute(select(func.count(Finding.id)).where(
        Finding.collected_at < cutoff))).scalar() or 0
    job_count = (await db.execute(select(func.count(Job.id)).where(
        Job.finished_at < cutoff))).scalar() or 0
    if data.dry_run:
        return {"dry_run": True, "would_delete": {"findings": find_count, "jobs": job_count},
                "cutoff": cutoff.isoformat()}
    await db.execute(delete(Finding).where(Finding.collected_at < cutoff))
    await db.execute(delete(Job).where(Job.finished_at < cutoff))
    db.add(AuditLog(user_id=u.id, action="retention.purge",
                    detail={"findings": find_count, "jobs": job_count,
                            "cutoff": cutoff.isoformat()}))
    await db.commit()
    return {"dry_run": False, "deleted": {"findings": find_count, "jobs": job_count}}
