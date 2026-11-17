"""Investigation timeline — ordered union of jobs and findings."""
from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Job, Finding

router = APIRouter()


@router.get("/{inv_id}")
async def timeline(inv_id: str, _: object = Depends(current_user), db: AsyncSession = Depends(get_session)):
    jobs = (await db.execute(select(Job).where(Job.investigation_id == inv_id))).scalars().all()
    finds = (await db.execute(select(Finding).where(Finding.investigation_id == inv_id))).scalars().all()
    events = []
    for j in jobs:
        if j.started_at:
            events.append({"at": j.started_at.isoformat(), "kind": "job.started",
                           "module": j.module, "job_id": j.id})
        if j.finished_at:
            events.append({"at": j.finished_at.isoformat(), "kind": f"job.{j.status}",
                           "module": j.module, "job_id": j.id,
                           "result": j.result, "error": j.error})
    for f in finds:
        events.append({"at": f.collected_at.isoformat(), "kind": "finding",
                       "module": f.module, "source": f.source, "finding_kind": f.kind,
                       "confidence": f.confidence})
    events.sort(key=lambda e: e["at"])
    return events
