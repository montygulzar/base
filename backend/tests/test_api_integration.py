"""API integration tests driven by fastapi's TestClient.

Uses a module-scoped sqlite file configured BEFORE the app imports, so
all SQLAlchemy sessions point at the same database.
"""
import asyncio
import os
import tempfile
import pytest
from fastapi.testclient import TestClient

_tmp = tempfile.mkdtemp(prefix="base-it-")
_db = os.path.join(_tmp, "base.db")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_db}"
os.environ["JWT_SECRET"] = "test-secret"

from app.db import engine, Base, SessionLocal  # noqa: E402 (env set above)
from app.models import User  # noqa: E402
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


def _token(c):
    r = c.post("/api/auth/login", data={"username": "admin@base.app", "password": "admin"})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_modules_list_covers_core(client):
    h = _token(client)
    mods = {m["key"] for m in client.get("/api/modules", headers=h).json()}
    for k in ("domain", "ip", "email", "username", "passive_dns", "secrets_scan", "risk"):
        assert k in mods


def test_investigations_crud_and_ingest(client):
    h = _token(client)
    r = client.post("/api/investigations", headers=h,
                    json={"name": "it", "subjects": [{"type": "domain", "value": "example.com"}]})
    assert r.status_code == 200, r.text
    inv = r.json()["id"]
    assert len(client.get(f"/api/investigations/{inv}/subjects", headers=h).json()) == 1
    text = "1.2.3.4 CVE-2021-44228 example.com abc@example.com https://x.com/"
    r = client.post(f"/api/ingest/{inv}", headers=h, json={"text": text})
    assert r.status_code == 200
    assert r.json()["added"] >= 4
    s = client.get(f"/api/stats/{inv}", headers=h).json()
    assert s["entities"] >= 4
    g = client.get(f"/api/graph/{inv}", headers=h).json()
    assert len(g["nodes"]) >= 4


def test_compare_two(client):
    h = _token(client)
    a = client.post("/api/investigations", headers=h, json={"name": "A"}).json()["id"]
    b = client.post("/api/investigations", headers=h, json={"name": "B"}).json()["id"]
    client.post(f"/api/ingest/{a}", headers=h, json={"text": "1.1.1.1 shared.com"})
    client.post(f"/api/ingest/{b}", headers=h, json={"text": "2.2.2.2 shared.com"})
    d = client.get(f"/api/compare/{a}/vs/{b}", headers=h).json()
    assert d["overlap_count"] >= 1
    assert ("ip", "1.1.1.1") in {(x["type"], x["value"]) for x in d["only_a"]}
    assert ("ip", "2.2.2.2") in {(x["type"], x["value"]) for x in d["only_b"]}
