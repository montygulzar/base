"""Create tables and seed the bootstrap admin on container start."""
import asyncio
import logging
from sqlalchemy import select
from .config import get_settings
from .db import engine, SessionLocal, Base
from .models import User, IntegrationStatus
from .auth import hash_password
from . import integrations  # registers modules
from .integrations import REGISTRY as INTEG_REG

log = logging.getLogger("bootstrap")
logging.basicConfig(level=get_settings().LOG_LEVEL)


async def _run():
    s = get_settings()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with SessionLocal() as db:
        if not (await db.execute(select(User).where(User.email == s.BOOTSTRAP_ADMIN_EMAIL))).scalar_one_or_none():
            db.add(User(email=s.BOOTSTRAP_ADMIN_EMAIL, password_hash=hash_password(s.BOOTSTRAP_ADMIN_PASSWORD), role="admin"))
            log.info("seeded admin %s", s.BOOTSTRAP_ADMIN_EMAIL)
        for name, meta in INTEG_REG.items():
            row = await db.get(IntegrationStatus, name)
            if not row:
                db.add(IntegrationStatus(name=name, configured=bool(meta.get("configured"))))
            else:
                row.configured = bool(meta.get("configured"))
        await db.commit()
    log.info("bootstrap complete")


if __name__ == "__main__":
    asyncio.run(_run())
