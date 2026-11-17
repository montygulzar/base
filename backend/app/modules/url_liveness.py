"""URL liveness probe.

Walks every `url` entity in the investigation and does a HEAD request
(fallback to GET). Records status / final URL / content length / server.
Useful to triage which discovered URLs are actually live.
"""
from __future__ import annotations
import asyncio
import httpx
from sqlalchemy import select
from ..db import SessionLocal
from ..models import Entity
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding as F, CollectionResult, RunContext, register


async def _probe(c: httpx.AsyncClient, url: str) -> dict:
    try:
        assert_public(url)
    except SSRFBlocked as e:
        return {"url": url, "error": f"ssrf_blocked: {e}"}
    try:
        r = await c.head(url, timeout=10, follow_redirects=True)
        if r.status_code >= 400 or r.status_code == 405:
            r = await c.get(url, timeout=12, follow_redirects=True)
        return {"url": url, "status": r.status_code, "final_url": str(r.url),
                "server": r.headers.get("server"), "length": r.headers.get("content-length")}
    except Exception as e:
        return {"url": url, "error": str(e)[:200]}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    async with SessionLocal() as db:
        urls = [e.value for e in (await db.execute(
            select(Entity).where(Entity.investigation_id == ctx.investigation_id,
                                 Entity.type == "url")
        )).scalars().all() if e.value.startswith("http")]
    urls = list(dict.fromkeys(urls))[:200]
    sem = asyncio.Semaphore(16)
    async def guarded(u, c):
        async with sem:
            return await _probe(c, u)
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        results = await asyncio.gather(*[guarded(u, c) for u in urls])
    live = [r for r in results if r.get("status") and r["status"] < 400]
    out.findings.append(F("url_liveness", "probe",
                          {"total": len(results), "live": len(live),
                           "results": results[:200]}, 0.9))
    return out


register(Module(
    key="url_liveness",
    name="URL liveness",
    subject_types=["domain", "ip", "url", "email", "username", "company",
                   "media", "document", "phone"],
    description="HEAD/GET every `url` entity; records status + final URL.",
    run=run,
))
