"""Public S3 bucket enumeration.

Given a company / name keyword, generate common bucket patterns and
HEAD-check them against s3.amazonaws.com. 200 = exists (public or
private but reachable). 403 = exists but access-denied. 404 = free.
"""
from __future__ import annotations
import asyncio
import httpx
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

SUFFIXES = ["", "-prod", "-staging", "-dev", "-backup", "-backups", "-data",
            "-assets", "-static", "-media", "-public", "-private",
            "-uploads", "-logs", "-reports", "-archive", "-test"]
PREFIXES = ["", "prod-", "dev-", "staging-", "backup-", "data-", "static-",
            "media-", "assets-"]


async def _head(c: httpx.AsyncClient, bucket: str) -> dict:
    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        r = await c.head(url, timeout=6, follow_redirects=True)
        return {"bucket": bucket, "status": r.status_code,
                "exists": r.status_code in (200, 403),
                "public": r.status_code == 200}
    except Exception as e:
        return {"bucket": bucket, "error": str(e)[:200]}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    name = (subject or "").strip().lower().replace(" ", "-").replace(".", "-")
    if not name:
        out.findings.append(Finding("s3_enum", "invalid_input", {"input": subject}, 0.1))
        return out
    candidates = set()
    for p in PREFIXES:
        for s in SUFFIXES:
            cand = f"{p}{name}{s}".strip("-")
            if 3 <= len(cand) <= 63 and all(c.isalnum() or c in "-." for c in cand):
                candidates.add(cand)
    candidates = sorted(candidates)[:200]
    sem = asyncio.Semaphore(16)
    async def guarded(c, b):
        async with sem:
            return await _head(c, b)
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        results = await asyncio.gather(*[guarded(c, b) for b in candidates])
    hits = [r for r in results if r.get("exists")]
    out.findings.append(Finding("s3_enum", "scan",
                                {"candidates_checked": len(candidates),
                                 "hits": hits,
                                 "public_hits": [h for h in hits if h.get("public")]},
                                0.9 if hits else 0.5))
    for h in hits:
        out.entities.append(Entity("url", f"https://{h['bucket']}.s3.amazonaws.com/",
                                   {"public": h.get("public"), "from": "s3_enum"}, 0.8))
    return out


register(Module(
    key="s3_enum",
    name="S3 bucket enumeration",
    subject_types=["company", "domain", "username"],
    description="Common-pattern public S3 bucket discovery.",
    run=run,
))
