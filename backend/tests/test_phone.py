import asyncio
from app.modules.phone import run
from app.modules.base import RunContext
from app.config import get_settings


def test_phone_valid():
    s = get_settings()
    ctx = RunContext(investigation_id="x", subject_id="y", settings=s)
    r = asyncio.run(run("+14155552671", ctx))
    kinds = {f.kind for f in r.findings}
    assert "parsed" in kinds
    ents = {(e.type, e.value) for e in r.entities}
    assert any(t == "phone" for t, _ in ents)


def test_phone_invalid():
    s = get_settings()
    ctx = RunContext(investigation_id="x", subject_id="y", settings=s)
    r = asyncio.run(run("not-a-number", ctx))
    assert any(f.kind == "invalid_input" for f in r.findings)
