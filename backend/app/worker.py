"""arq worker — moves orchestration off the API process."""
from __future__ import annotations
import logging
from arq.connections import RedisSettings
from .config import get_settings
from .orchestrator import plan_and_run

log = logging.getLogger("worker")
logging.basicConfig(level=get_settings().LOG_LEVEL)


async def run_investigation(ctx, investigation_id: str, modules: list[str] | None, subject_ids: list[str] | None):
    log.info("worker running inv=%s mods=%s", investigation_id, modules)
    jobs = await plan_and_run(investigation_id, modules, subject_ids)
    return {"jobs": jobs}


class WorkerSettings:
    functions = [run_investigation]
    redis_settings = RedisSettings.from_dsn(get_settings().REDIS_URL)
    max_jobs = 4
