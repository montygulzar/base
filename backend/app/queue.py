"""Enqueue shim.

If redis+arq are reachable, hand the job off to the worker. Otherwise
fall through to an in-process asyncio task (dev/sqlite mode).

This keeps the API response fast and lets `docker compose` run horizontally
scale the worker while single-process `uvicorn app.main:app` still works.
"""
from __future__ import annotations
import asyncio
import logging
from .config import get_settings
from .orchestrator import plan_and_run

log = logging.getLogger("queue")
_arq_pool = None


async def _get_pool():
    global _arq_pool
    if _arq_pool is not None:
        return _arq_pool
    try:
        from arq import create_pool
        from arq.connections import RedisSettings
        _arq_pool = await create_pool(RedisSettings.from_dsn(get_settings().REDIS_URL))
        log.info("arq pool connected")
        return _arq_pool
    except Exception as e:
        log.info("no arq pool (%s); falling back to in-process", e)
        _arq_pool = False
        return False


async def enqueue_run(inv_id: str, modules: list[str] | None, subject_ids: list[str] | None):
    pool = await _get_pool()
    if pool:
        await pool.enqueue_job("run_investigation", inv_id, modules, subject_ids)
        return
    # in-process fallback — task is retained on the loop
    asyncio.create_task(plan_and_run(inv_id, modules, subject_ids))
