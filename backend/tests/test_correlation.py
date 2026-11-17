"""Correlation test — runs against a real in-memory sqlite DB with seeded
entities and checks the correlator produces the expected edges.
"""
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.db import Base
from app import models
from app.correlation import correlate_investigation


def test_correlation_shares_ip():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async def go():
        async with engine.begin() as c:
            await c.run_sync(Base.metadata.create_all)
        async with Session() as db:
            u = models.User(email="x@y.z", password_hash="x", role="admin"); db.add(u); await db.flush()
            inv = models.Investigation(name="t", owner_id=u.id); db.add(inv); await db.flush()
            d1 = models.Entity(investigation_id=inv.id, type="domain", value="a.com", confidence=0.9)
            d2 = models.Entity(investigation_id=inv.id, type="domain", value="b.com", confidence=0.9)
            ip = models.Entity(investigation_id=inv.id, type="ip", value="1.2.3.4", confidence=0.9)
            db.add_all([d1, d2, ip]); await db.flush()
            db.add(models.Relationship(investigation_id=inv.id, src_id=d1.id, dst_id=ip.id,
                                       type="resolves_to", source="t", confidence=0.9))
            db.add(models.Relationship(investigation_id=inv.id, src_id=d2.id, dst_id=ip.id,
                                       type="resolves_to", source="t", confidence=0.9))
            await db.commit()
            inv_id = inv.id
        async with Session() as db:
            await correlate_investigation(db, inv_id)
        async with Session() as db:
            from sqlalchemy import select
            rels = (await db.execute(select(models.Relationship).where(
                models.Relationship.investigation_id == inv_id,
                models.Relationship.type == "co_hosted_with",
            ))).scalars().all()
            assert len(rels) == 1, f"expected 1 co_hosted_with, got {len(rels)}"

    asyncio.run(go())
