"""Per-module runtime stats: average duration, success / error / running
counts. Admin / analyst view for triage.
"""
from __future__ import annotations
from collections import defaultdict
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Job

router = APIRouter()


@router.get("")
async def module_stats(_: object = Depends(current_user),
                       db: AsyncSession = Depends(get_session)):
    jobs = (await db.execute(select(Job))).scalars().all()
    buckets: dict[str, dict] = defaultdict(lambda: {"total": 0, "done": 0, "error": 0,
                                                    "running": 0, "queued": 0,
                                                    "total_seconds": 0.0, "runs_with_duration": 0})
    for j in jobs:
        b = buckets[j.module]
        b["total"] += 1
        b[j.status] = b.get(j.status, 0) + 1
        if j.started_at and j.finished_at:
            b["total_seconds"] += (j.finished_at - j.started_at).total_seconds()
            b["runs_with_duration"] += 1
    out = []
    for name, b in buckets.items():
        out.append({
            "module": name,
            "total": b["total"],
            "done": b.get("done", 0),
            "error": b.get("error", 0),
            "running": b.get("running", 0),
            "queued": b.get("queued", 0),
            "avg_duration_seconds": (b["total_seconds"] / b["runs_with_duration"])
                                     if b["runs_with_duration"] else None,
            "success_rate": round(b.get("done", 0) / b["total"], 3) if b["total"] else None,
        })
    out.sort(key=lambda r: r["total"], reverse=True)
    return out
