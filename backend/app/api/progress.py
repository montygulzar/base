"""Investigation progress summary.

Returns the fraction done of a scheduled plan.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Job, Investigation

router = APIRouter()


@router.get("/{inv_id}")
async def progress(inv_id: str, _: object = Depends(current_user),
                   db: AsyncSession = Depends(get_session)):
    inv = await db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "not found")
    jobs = (await db.execute(select(Job).where(Job.investigation_id == inv_id))).scalars().all()
    total = len(jobs)
    from collections import Counter
    c = Counter(j.status for j in jobs)
    done = c.get("done", 0) + c.get("error", 0)
    percent = (done / total * 100) if total else 0
    return {
        "total": total, "done": done, "percent": round(percent, 1),
        "status_counts": dict(c), "investigation_status": inv.status,
    }
