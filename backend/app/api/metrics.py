"""Prometheus-style scrape endpoint.

Minimal counters and gauges derived from the DB. No prometheus_client
dependency — plain text exposition format.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import get_session
from ..models import Investigation, Entity, Finding, Job, User

router = APIRouter()


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics(db: AsyncSession = Depends(get_session)):
    inv = (await db.execute(select(func.count(Investigation.id)))).scalar() or 0
    users = (await db.execute(select(func.count(User.id)))).scalar() or 0
    ents = (await db.execute(select(func.count(Entity.id)))).scalar() or 0
    finds = (await db.execute(select(func.count(Finding.id)))).scalar() or 0
    jobs = (await db.execute(select(func.count(Job.id)))).scalar() or 0
    running = (await db.execute(select(func.count(Job.id)).where(Job.status == "running"))).scalar() or 0
    errored = (await db.execute(select(func.count(Job.id)).where(Job.status == "error"))).scalar() or 0
    lines = [
        "# HELP base_investigations_total Total investigations stored.",
        "# TYPE base_investigations_total gauge",
        f"base_investigations_total {inv}",
        "# HELP base_users_total Total user accounts.",
        "# TYPE base_users_total gauge",
        f"base_users_total {users}",
        "# HELP base_entities_total Total entities across all investigations.",
        "# TYPE base_entities_total gauge",
        f"base_entities_total {ents}",
        "# HELP base_findings_total Total findings across all investigations.",
        "# TYPE base_findings_total gauge",
        f"base_findings_total {finds}",
        "# HELP base_jobs_total Collection jobs by current status.",
        "# TYPE base_jobs_total gauge",
        f"base_jobs_total{{status=\"all\"}} {jobs}",
        f"base_jobs_total{{status=\"running\"}} {running}",
        f"base_jobs_total{{status=\"error\"}} {errored}",
    ]
    return "\n".join(lines) + "\n"
