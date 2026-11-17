"""Cloud bucket enumeration — Azure Blob + GCS.

Same approach as s3_enum but against:
- Azure:  https://{bucket}.blob.core.windows.net/
- GCS:    https://storage.googleapis.com/{bucket}/
"""
from __future__ import annotations
import asyncio
import httpx
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

SUFFIXES = ["", "-prod", "-staging", "-dev", "-backup", "-data", "-assets",
            "-static", "-media", "-public", "-uploads", "-logs"]


async def _azure(c: httpx.AsyncClient, b: str) -> dict:
    try:
        r = await c.head(f"https://{b}.blob.core.windows.net/", timeout=6,
                         follow_redirects=True)
        return {"bucket": b, "status": r.status_code,
                "exists": r.status_code in (200, 400, 403),
                "public": r.status_code == 200}
    except Exception as e:
        return {"bucket": b, "error": str(e)[:200]}


async def _gcs(c: httpx.AsyncClient, b: str) -> dict:
    try:
        r = await c.head(f"https://storage.googleapis.com/{b}/", timeout=6,
                         follow_redirects=True)
        return {"bucket": b, "status": r.status_code,
                "exists": r.status_code in (200, 403),
                "public": r.status_code == 200}
    except Exception as e:
        return {"bucket": b, "error": str(e)[:200]}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    name = (subject or "").strip().lower().replace(" ", "-").replace(".", "-")
    if not name:
        out.findings.append(Finding("cloud_bucket", "invalid_input", {"input": subject}, 0.1))
        return out
    candidates = sorted({f"{name}{s}".strip("-") for s in SUFFIXES
                         if 3 <= len(f"{name}{s}".strip("-")) <= 63})
    sem = asyncio.Semaphore(16)

    async def guarded(fn, c, b):
        async with sem:
            return await fn(c, b)

    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        azure = await asyncio.gather(*[guarded(_azure, c, b) for b in candidates])
        gcs = await asyncio.gather(*[guarded(_gcs, c, b) for b in candidates])

    az_hits = [r for r in azure if r.get("exists")]
    gcs_hits = [r for r in gcs if r.get("exists")]
    out.findings.append(Finding("cloud_bucket", "azure",
                                {"candidates": len(candidates),
                                 "hits": az_hits},
                                0.9 if az_hits else 0.5))
    out.findings.append(Finding("cloud_bucket", "gcs",
                                {"candidates": len(candidates),
                                 "hits": gcs_hits},
                                0.9 if gcs_hits else 0.5))
    for h in az_hits:
        out.entities.append(Entity("url", f"https://{h['bucket']}.blob.core.windows.net/",
                                   {"provider": "azure", "public": h.get("public")}, 0.8))
    for h in gcs_hits:
        out.entities.append(Entity("url", f"https://storage.googleapis.com/{h['bucket']}/",
                                   {"provider": "gcs", "public": h.get("public")}, 0.8))
    return out


register(Module(
    key="cloud_bucket",
    name="Cloud bucket enum (Azure + GCS)",
    subject_types=["company", "domain", "username"],
    description="HEAD-sweep Azure Blob and Google Cloud Storage patterns.",
    run=run,
))
