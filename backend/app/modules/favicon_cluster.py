"""Favicon cluster.

Looks at every favicon mmh3 hash recorded in the investigation (from the
`favicon` module or external ingestion) and reports clusters of hosts
sharing the same hash — classic pivot for finding infra operated by the
same party.
"""
from __future__ import annotations
from collections import defaultdict
from sqlalchemy import select
from ..db import SessionLocal
from ..models import Finding
from .base import Module, Finding as F, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    async with SessionLocal() as db:
        finds = (await db.execute(
            select(Finding).where(Finding.investigation_id == ctx.investigation_id,
                                  Finding.source == "favicon", Finding.kind == "hash")
        )).scalars().all()
    by_hash: dict[int, list[str]] = defaultdict(list)
    for f in finds:
        d = f.data or {}
        h = d.get("mmh3")
        u = d.get("url")
        if h is not None and u:
            by_hash[h].append(u)
    clusters = {h: urls for h, urls in by_hash.items() if len(urls) > 1}
    out.findings.append(F("favicon_cluster", "summary",
                          {"distinct_hashes": len(by_hash),
                           "shared_clusters": len(clusters),
                           "clusters": {str(h): urls for h, urls in clusters.items()}},
                          0.9 if clusters else 0.4))
    return out


register(Module(
    key="favicon_cluster",
    name="Favicon cluster",
    subject_types=["domain", "ip", "url", "email", "username", "company",
                   "media", "document", "phone"],
    description="Finds hosts sharing the same favicon mmh3 hash.",
    run=run,
))
