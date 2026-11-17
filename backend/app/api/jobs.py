"""Job retry — re-queue an errored or cancelled job for a single
module × subject. Also supports redriving every failed job in an
investigation.
"""
from __future__ import annotations
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import require_role
from ..db import get_session
from ..models import Job
from ..queue import enqueue_run

router = APIRouter()


@router.post("/{job_id}/retry")
async def retry(job_id: str, u=Depends(require_role("admin", "analyst")),
                db: AsyncSession = Depends(get_session)):
    j = await db.get(Job, job_id)
    if not j:
        raise HTTPException(404, "job not found")
    if j.status not in ("error", "cancelled"):
        raise HTTPException(400, f"cannot retry job in state '{j.status}'")
    # reset fields and enqueue as a one-shot
    j.status = "queued"; j.error = ""; j.started_at = None; j.finished_at = None
    j.result = {}
    await db.commit()
    await enqueue_run(j.investigation_id, [j.module],
                      [j.subject_id] if j.subject_id else None)
    return {"id": j.id, "status": "queued"}


@router.post("/{inv_id}/redrive_failed")
async def redrive_failed(inv_id: str, u=Depends(require_role("admin", "analyst")),
                         db: AsyncSession = Depends(get_session)):
    failed = (await db.execute(
        select(Job).where(Job.investigation_id == inv_id, Job.status == "error")
    )).scalars().all()
    if not failed:
        return {"redriven": 0}
    for j in failed:
        j.status = "queued"; j.error = ""; j.started_at = None; j.finished_at = None
        j.result = {}
    await db.commit()
    # one bulk enqueue — we can't re-use existing job rows directly because
    # plan_and_run creates new ones. Instead re-run the specific module
    # keys on the subject ids.
    modules = sorted({j.module for j in failed})
    subject_ids = sorted({j.subject_id for j in failed if j.subject_id})
    await enqueue_run(inv_id, modules, subject_ids or None)
    return {"redriven": len(failed), "modules": modules}
