import asyncio
from app.modules.email_permute import run
from app.modules.base import RunContext
from app.config import get_settings


def test_permute():
    r = asyncio.run(run("John Smith @ example.com",
                        RunContext(investigation_id="x", subject_id="y", settings=get_settings())))
    emails = [e.value for e in r.entities if e.type == "email"]
    assert "john.smith@example.com" in emails
    assert "jsmith@example.com" in emails
    assert "j.smith@example.com" in emails


def test_bad_input():
    r = asyncio.run(run("not a thing",
                        RunContext(investigation_id="x", subject_id="y", settings=get_settings())))
    assert any(f.kind == "invalid_input" for f in r.findings)
