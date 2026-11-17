import asyncio, json
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.db import Base
from app import models
from app.api.stix import export_stix, import_stix


class _DummyReq:
    def __init__(self, payload): self.payload = payload
    async def json(self): return self.payload


def test_stix_roundtrip():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async def go():
        async with engine.begin() as c:
            await c.run_sync(Base.metadata.create_all)
        # Seed an investigation with a few entities + a relationship
        async with Session() as db:
            u = models.User(email="x@y.z", password_hash="x", role="admin"); db.add(u); await db.flush()
            inv = models.Investigation(name="t", owner_id=u.id); db.add(inv); await db.flush()
            d = models.Entity(investigation_id=inv.id, type="domain", value="a.com", confidence=0.9)
            ip = models.Entity(investigation_id=inv.id, type="ip",     value="1.2.3.4", confidence=0.9)
            cve = models.Entity(investigation_id=inv.id, type="cve",    value="CVE-2024-0001", confidence=0.8)
            db.add_all([d, ip, cve]); await db.flush()
            db.add(models.Relationship(investigation_id=inv.id, src_id=d.id, dst_id=ip.id,
                                       type="resolves_to", source="t", confidence=0.9))
            await db.commit()
            inv_id = inv.id
        async with Session() as db:
            resp = await export_stix(inv_id, _=None, db=db)
            bundle = json.loads(resp.body)
            assert bundle["type"] == "bundle"
            types = {o["type"] for o in bundle["objects"]}
            assert {"domain-name", "ipv4-addr", "vulnerability", "relationship"} <= types

        # Import into a fresh investigation
        async with Session() as db:
            inv2 = models.Investigation(name="t2", owner_id=u.id); db.add(inv2); await db.commit()
            inv2_id = inv2.id
        class U: id = "fake"
        async with Session() as db:
            summary = await import_stix(inv2_id, _DummyReq(bundle), u=U(), db=db)
            assert summary["added_entities"] >= 3
            assert summary["added_relationships"] >= 1

    asyncio.run(go())
