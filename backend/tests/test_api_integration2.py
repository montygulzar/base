"""Integration tests for share, path, templates, graph filter, retention."""
import os, tempfile, asyncio, pytest
from fastapi.testclient import TestClient

_tmp = tempfile.mkdtemp(prefix="base-it2-")
_db = os.path.join(_tmp, "base.db")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_db}"
os.environ["JWT_SECRET"] = "test-secret-2"

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
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def test_template_create_instantiate(client):
    h = _tok(client)
    r = client.post("/api/templates", headers=h, json={
        "name": f"t-{os.urandom(3).hex()}", "description": "test",
        "modules": {"domain": ["domain"]},
    })
    assert r.status_code == 200
    tid = r.json()["id"]
    r2 = client.post(f"/api/templates/{tid}/instantiate", headers=h, json={
        "name": "from-template",
        "subjects": [{"type": "domain", "value": "example.com"}],
        "run": False,
    })
    assert r2.status_code == 200
    inv_id = r2.json()["id"]
    subs = client.get(f"/api/investigations/{inv_id}/subjects", headers=h).json()
    assert any(s["value"] == "example.com" for s in subs)


def test_inv_tags_set_get(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "tags"}).json()["id"]
    r = client.put(f"/api/inv_tags/{inv}", headers=h, json={"tags": ["phishing", "urgent"]})
    assert r.status_code == 200
    assert "phishing" in r.json()["tags"]
    assert client.get(f"/api/inv_tags/{inv}", headers=h).json()["tags"] == ["phishing", "urgent"]


def test_graph_min_confidence(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "filt"}).json()["id"]
    # seed entities directly via SessionLocal
    async def seed():
        async with SessionLocal() as db:
            a = Entity(investigation_id=inv, type="domain", value="low.com", confidence=0.3)
            b = Entity(investigation_id=inv, type="domain", value="high.com", confidence=0.9)
            db.add_all([a, b]); await db.commit()
    asyncio.run(seed())
    g_all = client.get(f"/api/graph/{inv}", headers=h).json()
    g_hi  = client.get(f"/api/graph/{inv}?min_confidence=0.5", headers=h).json()
    all_vals = {n["value"] for n in g_all["nodes"]}
    hi_vals = {n["value"] for n in g_hi["nodes"]}
    assert "low.com" in all_vals and "high.com" in all_vals
    assert "low.com" not in hi_vals and "high.com" in hi_vals


def test_path_finds_two_hop(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "path"}).json()["id"]
    ids = {}
    async def seed():
        async with SessionLocal() as db:
            a = Entity(investigation_id=inv, type="domain", value="a.com", confidence=0.9)
            b = Entity(investigation_id=inv, type="ip",     value="1.1.1.1", confidence=0.9)
            c = Entity(investigation_id=inv, type="domain", value="c.com", confidence=0.9)
            db.add_all([a, b, c]); await db.flush()
            db.add(Relationship(investigation_id=inv, src_id=a.id, dst_id=b.id,
                                type="resolves_to", source="t", confidence=0.9))
            db.add(Relationship(investigation_id=inv, src_id=c.id, dst_id=b.id,
                                type="resolves_to", source="t", confidence=0.9))
            await db.commit()
            ids["a"] = a.id; ids["c"] = c.id
    asyncio.run(seed())
    r = client.get(f"/api/path/{inv}?src={ids['a']}&dst={ids['c']}", headers=h).json()
    assert r["found"] is True
    assert r["length"] == 2
    values = [n["value"] for n in r["nodes"]]
    assert values == ["a.com", "1.1.1.1", "c.com"] or values == ["c.com", "1.1.1.1", "a.com"]


def test_retention_dry_run(client):
    h = _tok(client)
    r = client.post("/api/retention", headers=h, json={"older_than_days": 1, "dry_run": True})
    assert r.status_code == 200
    assert r.json()["dry_run"] is True


def test_share_mint_and_view(client):
    h = _tok(client)
    inv = client.post("/api/investigations", headers=h, json={"name": "share"}).json()["id"]
    r = client.post(f"/api/share/{inv}", headers=h, json={"ttl_hours": 1})
    assert r.status_code == 200
    token = r.json()["token"]
    # share endpoint needs NO auth
    r2 = client.get(f"/api/share/{token}")
    assert r2.status_code == 200
    assert r2.json()["investigation"]["id"] == inv
