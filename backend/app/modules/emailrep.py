"""EmailRep — email reputation scoring (free tier, no key required for
low volume; higher limits with EMAILREP_API_KEY).
"""
from __future__ import annotations
import httpx
from ..config import get_settings
from ..utils.validators import is_email
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip().lower()
    if not is_email(v):
        out.findings.append(Finding("emailrep", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("email", v, {}, 0.95))
    headers = {"user-agent": "base-osint/0.1", "accept": "application/json"}
    key = getattr(s, "EMAILREP_API_KEY", "") or ""
    if key:
        headers["key"] = key
    async with httpx.AsyncClient(headers=headers) as c:
        try:
            r = await c.get(f"https://emailrep.io/{v}", timeout=15)
            if r.status_code == 200:
                out.findings.append(Finding("emailrep", "reputation", r.json(), 0.9))
            elif r.status_code == 429:
                out.findings.append(Finding("emailrep", "rate_limited", {}, 0.2))
            else:
                out.findings.append(Finding("emailrep", "http_error",
                                            {"status": r.status_code, "body": r.text[:200]}, 0.1))
        except Exception as e:
            out.findings.append(Finding("emailrep", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="emailrep",
    name="EmailRep",
    subject_types=["email"],
    description="Email reputation + suspicious / malicious scoring.",
    run=run,
))
