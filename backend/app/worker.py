"""arq worker — moves orchestration off the API process.

Also hosts the scheduler cron: every 60s it looks for schedules whose
next_run_at <= now and enqueues a run.
"""
from __future__ import annotations
import logging
from datetime import datetime, timedelta
from arq.connections import RedisSettings
from arq import cron
from sqlalchemy import select
from .config import get_settings
from .db import SessionLocal
from .models import Schedule
from .orchestrator import plan_and_run

log = logging.getLogger("worker")
logging.basicConfig(level=get_settings().LOG_LEVEL)


async def run_investigation(ctx, investigation_id: str, modules: list[str] | None, subject_ids: list[str] | None):
    log.info("worker running inv=%s mods=%s", investigation_id, modules)
    jobs = await plan_and_run(investigation_id, modules, subject_ids)
    return {"jobs": jobs}


async def tick_scheduler(ctx):
    now = datetime.utcnow()
    async with SessionLocal() as db:
        rows = (await db.execute(
            select(Schedule).where(Schedule.enabled == True, Schedule.next_run_at <= now)
        )).scalars().all()
        for s in rows:
            try:
                await ctx["redis"].enqueue_job(
                    "run_investigation",
                    s.investigation_id,
                    (s.modules or {}).get("keys") or None,
                    None,
                )
                s.last_run_at = now
                s.next_run_at = now + timedelta(seconds=s.interval_seconds)
            except Exception as e:
                log.exception("scheduler enqueue failed: %s", e)
        await db.commit()
    return {"fired": len(rows)}


class WorkerSettings:
    functions = [run_investigation, tick_scheduler]
    cron_jobs = [cron(tick_scheduler, minute=set(range(0, 60)))]  # every minute
    redis_settings = RedisSettings.from_dsn(get_settings().REDIS_URL)
    max_jobs = 4
