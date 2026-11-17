"""Integration coverage for degrees, mermaid, seal, zip, version, fuzzy."""
import os, tempfile, asyncio, pytest
from fastapi.testclient import TestClient

_tmp = tempfile.mkdtemp(prefix="base-it3-")
_db = os.path.join(_tmp, "base.db")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_db}"
os.environ["JWT_SECRET"] = "test-secret-3"

from app.db import engine, Base, SessionLocal  # noqa: E402
from app.models import User, Investigation, Entity, Relationship  # noqa: E402
from app.auth import hash_password  # noqa: E402
from app.main import app  # noqa: E402


async def _init():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with SessionLocal() as db:
        from sqlalchemy import select
        if not (await db.execute(select(User).where(User.email == "admin@base.app"))).scalar_one_or_none():
            db.add(User(email="admin@base.app", password_hash=hash_password("admin"), role="admin"))
            await db.commit()
asyncio.run(_init())


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def _tok(c):
    r = c.post("/api/auth/login", data={"username": "admin@base.app", "password": "admin"})
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def _seed_small_graph(inv_id: str):
    async def seed():
        async with SessionLocal() as db:
            a = Entity(investigation_id=inv_id, type="domain", value="hub.com", confidence=0.9)
            b = Entity(investigation_id=inv_id, type="ip",     value="1.1.1.1", confidence=0.9)
            c = Entity(investigation_id=inv_id, type="domain", value="leaf.com", confidence=0.9)
            db.add_all([a, b, c]); await db.flush()
            db.add(Relationship(investigation_id=inv_id, src_id=a.id, dst_id=b.id,
                                type="resolves_to", source="t", confidence=0.9))
            db.add(Relationship(investigation_id=inv_id, src_id=c.id, dst_id=b.id,
                                type="resolves_to", source="t", confidence=0.9))
            await db.commit()
    asyncio.run(seed())


def test_degrees(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "deg"}).json()["id"]
    _seed_small_graph(inv)
    rows = client.get(f"/api/degrees/{inv}", headers=h).json()
    top = rows[0]
    assert top["value"] == "1.1.1.1"
    assert top["degree"] == 2


def test_mermaid(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "mmd"}).json()["id"]
    _seed_small_graph(inv)
    body = client.get(f"/api/mermaid/{inv}.mmd", headers=h).text
    assert body.startswith("graph LR")
    assert "resolves_to" in body


def test_seal_unseal(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "seal"}).json()["id"]
    r = client.post(f"/api/seal/{inv}/seal", headers=h); assert r.status_code == 200
    assert r.json()["status"] == "sealed"
    r = client.post(f"/api/seal/{inv}/unseal", headers=h); assert r.status_code == 200


def test_zip_bundle_bytes(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "zip"}).json()["id"]
    _seed_small_graph(inv)
    r = client.get(f"/api/zip/{inv}.zip", headers=h)
    assert r.status_code == 200
    assert r.content[:4] == b"PK\x03\x04"


def test_version(client):
    h = _tok(client)
    v = client.get("/api/version", headers=h).json()
    assert v["name"] == "base"
    assert v["modules"] >= 80


def test_fuzzy_match(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "fz"}).json()["id"]
    async def seed():
        async with SessionLocal() as db:
            db.add(Entity(investigation_id=inv, type="domain", value="example.com", confidence=0.9))
            await db.commit()
    asyncio.run(seed())
    hits = client.get("/api/fuzzy?q=exmple.com", headers=h).json()["hits"]
    assert hits, hits
    assert hits[0]["value"] == "example.com"
