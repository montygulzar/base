"""Integration coverage for CSV ingest, API keys, global search,
combined graph, backup round-trip.
"""
import os, tempfile, asyncio, io, csv, pytest
from fastapi.testclient import TestClient

_tmp = tempfile.mkdtemp(prefix="base-it4-")
_db = os.path.join(_tmp, "base.db")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_db}"
os.environ["JWT_SECRET"] = "test-secret-4"

from app.db import engine, Base, SessionLocal  # noqa: E402
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


def _tok(c):
    r = c.post("/api/auth/login", data={"username": "admin@base.app", "password": "admin"})
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def test_csv_ingest(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "csv"}).json()["id"]
    csv_body = "value,type\nexample.com,domain\n1.2.3.4,ip\nnotathing!,garbage\n"
    r = client.post(f"/api/csv_ingest/{inv}", headers=h,
                    files={"file": ("ioc.csv", csv_body, "text/csv")})
    assert r.status_code == 200
    body = r.json()
    assert body["added"] >= 2


def test_apikey_lifecycle(client):
    h = _tok(client)
    issue = client.post("/api/apikeys", headers=h, json={"label": "ci"}).json()
    assert issue["key"].startswith("base_")
    kid = issue["id"]
    lst = client.get("/api/apikeys", headers=h).json()
    assert any(k["id"] == kid for k in lst)
    rev = client.delete(f"/api/apikeys/{kid}", headers=h).json()
    assert rev["deleted"] == kid


def test_global_search(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "search-corpus"}).json()["id"]
    client.post(f"/api/ingest/{inv}", headers=h, json={"text": "example.com cve-2020-1 1.2.3.4"})
    r = client.get("/api/global_search?q=example", headers=h).json()
    assert any("example" in e["value"] for e in r["entities"])


def test_combined_graph(client):
    h = _tok(client)
    a = client.post("/api/investigations", headers=h, json={"name": "cg-a"}).json()["id"]
    b = client.post("/api/investigations", headers=h, json={"name": "cg-b"}).json()["id"]
    client.post(f"/api/ingest/{a}", headers=h, json={"text": "shared.com"})
    client.post(f"/api/ingest/{b}", headers=h, json={"text": "shared.com different.com"})
    r = client.post("/api/combined_graph", headers=h,
                    json={"investigation_ids": [a, b]}).json()
    vals = {n["value"] for n in r["nodes"]}
    assert "shared.com" in vals
    shared = next(n for n in r["nodes"] if n["value"] == "shared.com")
    assert len(shared["investigations"]) == 2


def test_backup_restore_roundtrip(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "round"}).json()["id"]
    client.post(f"/api/ingest/{inv}", headers=h, json={"text": "a.com 8.8.8.8"})
    dump = client.get(f"/api/backup/{inv}.base.json", headers=h).json()
    r = client.post("/api/backup/restore", headers=h, json=dump).json()
    assert r["entities_restored"] >= 2
    new_id = r["id"]
    g = client.get(f"/api/graph/{new_id}", headers=h).json()
    vals = {n["value"] for n in g["nodes"]}
    assert "a.com" in vals and "8.8.8.8" in vals
