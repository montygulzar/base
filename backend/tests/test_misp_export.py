import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.db import Base
from app import models
from app.api.misp import misp_event


def test_misp_event_shape():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async def go():
        async with engine.begin() as c:
            await c.run_sync(Base.metadata.create_all)
        async with Session() as db:
            u = models.User(email="x@y.z", password_hash="x", role="admin"); db.add(u); await db.flush()
            inv = models.Investigation(name="t1", owner_id=u.id); db.add(inv); await db.flush()
            db.add_all([
                models.Entity(investigation_id=inv.id, type="domain", value="example.com", confidence=0.9),
                models.Entity(investigation_id=inv.id, type="ip",     value="1.2.3.4",     confidence=0.9),
                models.Entity(investigation_id=inv.id, type="cve",    value="CVE-2024-0001", confidence=0.8),
                models.Entity(investigation_id=inv.id, type="file",   value="skipme",       confidence=0.9),
            ])
            await db.commit()
            inv_id = inv.id
        async with Session() as db:
            resp = await misp_event(inv_id, _=None, db=db)
            event = resp.body
        import json
        parsed = json.loads(event)
        assert parsed["Event"]["info"] == "t1"
        types = {a["type"] for a in parsed["Event"]["Attribute"]}
        assert {"domain", "ip-dst", "vulnerability"} <= types

    asyncio.run(go())
