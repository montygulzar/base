"""Platform analytics: daily counts of findings / jobs for the last N
days, grouped by module and source.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth import current_user
from ..db import get_session
from ..models import Finding, Job

router = APIRouter()


@router.get("")
async def analytics(days: int = 14, _: object = Depends(current_user),
                    db: AsyncSession = Depends(get_session)):
    days = max(1, min(days, 90))
    cutoff = datetime.utcnow() - timedelta(days=days)
    finds = (await db.execute(select(Finding).where(Finding.collected_at >= cutoff))).scalars().all()
    jobs = (await db.execute(select(Job).where(Job.created_at >= cutoff))).scalars().all()

    by_day: dict[str, int] = defaultdict(int)
    by_module: dict[str, int] = defaultdict(int)
    by_source: dict[str, int] = defaultdict(int)
    for f in finds:
        by_day[f.collected_at.strftime("%Y-%m-%d")] += 1
        by_module[f.module] += 1
        by_source[f.source] += 1

    job_by_status: dict[str, int] = defaultdict(int)
    for j in jobs:
        job_by_status[j.status] += 1

    return {
        "days": days,
        "finding_count": len(finds),
        "job_count": len(jobs),
        "findings_per_day": [{"date": d, "count": c}
                              for d, c in sorted(by_day.items())],
        "top_modules": sorted([{"module": k, "count": v} for k, v in by_module.items()],
                              key=lambda r: r["count"], reverse=True)[:30],
        "top_sources": sorted([{"source": k, "count": v} for k, v in by_source.items()],
                              key=lambda r: r["count"], reverse=True)[:30],
        "jobs_by_status": job_by_status,
    }
