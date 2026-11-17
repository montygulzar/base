"""Intelligence X — optional key. Searches public & darknet indexed data.

API docs: https://intelx.io/product (public endpoint: 2.intelx.io).
With no key, emits source_unavailable.
"""
from __future__ import annotations
import asyncio
import httpx
from ..utils.ratelimit import gate
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


BASE = "https://2.intelx.io"


async def _search(c: httpx.AsyncClient, key: str, term: str) -> dict:
    await gate("intelx")
    try:
        r = await c.post(f"{BASE}/intelligent/search",
                         headers={"x-key": key, "content-type": "application/json",
                                  "user-agent": "base-osint/0.1"},
                         json={"term": term, "maxresults": 50, "media": 0, "sort": 4, "terminate": []},
                         timeout=20)
        if r.status_code != 200:
            return {"error": f"search status={r.status_code}"}
        sid = (r.json() or {}).get("id")
        if not sid:
            return {"error": "no search id"}
        # Poll results
        for _ in range(8):
            await asyncio.sleep(1.5)
            rr = await c.get(f"{BASE}/intelligent/search/result",
                             params={"id": sid, "limit": 50},
                             headers={"x-key": key}, timeout=15)
            if rr.status_code == 200:
                j = rr.json() or {}
                if j.get("status") in (0, 1):  # 0 = success, 1 = partial
                    return {"records": j.get("records", []), "count": len(j.get("records", []))}
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip()
    if not v:
        return out
    if not getattr(s, "INTELX_API_KEY", ""):
        out.findings.append(Finding("intelx", "source_unavailable", {"reason": "no api key"}, 0.0))
        return out
    async with httpx.AsyncClient() as c:
        j = await _search(c, s.INTELX_API_KEY, v)
        out.findings.append(Finding("intelx", "search", j, 0.85 if "records" in j else 0.1))
        for rec in (j.get("records") or [])[:50]:
            name = rec.get("name") or ""
            system_id = rec.get("systemid") or ""
            if system_id:
                out.entities.append(Entity("url", f"https://intelx.io/?did={system_id}",
                                           {"from": "intelx", "bucket": rec.get("bucket")}, 0.7))
    return out


register(Module(
    key="intelx",
    name="Intelligence X",
    subject_types=["email", "domain", "username", "url", "ip"],
    description="Intelligence X search (public + darknet indices).",
    run=run,
))
