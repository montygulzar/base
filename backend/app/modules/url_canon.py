"""URL canonicalizer.

Strips default ports, lowercases host, sorts query params, removes
common trackers, collapses index.html. Deduplicates findings that are
really the same URL.
"""
from __future__ import annotations
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from sqlalchemy import select
from ..db import SessionLocal
from ..models import Entity
from .base import Module, Finding, CollectionResult, RunContext, register


TRACKING = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
            "gclid", "fbclid", "mc_cid", "mc_eid", "msclkid"}


def canon(url: str) -> str:
    try:
        p = urlsplit(url)
    except Exception:
        return url
    scheme = p.scheme.lower() or "http"
    host = (p.hostname or "").lower()
    port = p.port
    default = {"http": 80, "https": 443}.get(scheme)
    netloc = host
    if port and port != default:
        netloc = f"{host}:{port}"
    path = p.path or "/"
    if path.endswith("/index.html") or path.endswith("/index.htm"):
        path = path.rsplit("/", 1)[0] + "/"
    qs = sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                if k.lower() not in TRACKING)
    return urlunsplit((scheme, netloc, path, urlencode(qs), ""))


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    async with SessionLocal() as db:
        urls = (await db.execute(select(Entity).where(
            Entity.investigation_id == ctx.investigation_id,
            Entity.type == "url"))).scalars().all()
    buckets: dict[str, list[str]] = {}
    for u in urls:
        c = canon(u.value)
        buckets.setdefault(c, []).append(u.value)
    duplicates = {k: v for k, v in buckets.items() if len(v) > 1}
    out.findings.append(Finding("url_canon", "summary",
                                {"total_urls": len(urls),
                                 "distinct_canonical": len(buckets),
                                 "duplicate_groups": len(duplicates),
                                 "duplicates": {k: v for k, v in list(duplicates.items())[:50]}},
                                0.95))
    return out


register(Module(
    key="url_canon",
    name="URL canonicalizer",
    subject_types=["domain", "ip", "email", "username", "company",
                   "media", "document", "url", "phone", "btc", "eth"],
    description="Reports canonical duplicates among `url` entities.",
    run=run,
))
