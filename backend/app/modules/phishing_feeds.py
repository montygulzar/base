"""Phishing feeds — PhishTank (keyless public dump), OpenPhish, PhishStats.

Caches the feeds in-memory for the life of the process. Looks up the
subject URL / domain and reports hits.
"""
from __future__ import annotations
import httpx
from ..utils.validators import normalise_domain, is_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

_openphish_cache: set[str] | None = None
_phishstats_cache: list[dict] | None = None


async def _openphish(c: httpx.AsyncClient) -> set[str]:
    global _openphish_cache
    if _openphish_cache is not None:
        return _openphish_cache
    try:
        r = await c.get("https://openphish.com/feed.txt", timeout=25)
        if r.status_code == 200:
            _openphish_cache = {ln.strip() for ln in r.text.splitlines() if ln.strip().startswith("http")}
            return _openphish_cache
    except Exception:
        pass
    _openphish_cache = set()
    return _openphish_cache


async def _phishstats(c: httpx.AsyncClient) -> list[dict]:
    global _phishstats_cache
    if _phishstats_cache is not None:
        return _phishstats_cache
    try:
        r = await c.get("https://phishstats.info:2096/api/phishing?_sort=-id&_size=1000",
                        timeout=25)
        if r.status_code == 200:
            _phishstats_cache = r.json() or []
            return _phishstats_cache
    except Exception:
        pass
    _phishstats_cache = []
    return _phishstats_cache


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if "://" in v else "https://" + normalise_domain(v)
    domain = normalise_domain(url.split("//", 1)[-1].split("/", 1)[0])
    if is_domain(domain):
        out.entities.append(Entity("domain", domain, {}, 0.9))

    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        op = await _openphish(c)
        hits_op = [u for u in op if domain in u]
        out.findings.append(Finding("openphish", "match",
                                    {"domain": domain, "hits": hits_op[:50],
                                     "feed_size": len(op)},
                                    0.9 if hits_op else 0.4))
        ps = await _phishstats(c)
        hits_ps = [row for row in ps if domain and domain in (row.get("url") or "")][:50]
        out.findings.append(Finding("phishstats", "match",
                                    {"hits": hits_ps, "feed_size": len(ps)},
                                    0.9 if hits_ps else 0.4))
    return out


register(Module(
    key="phishing_feeds",
    name="Phishing feeds",
    subject_types=["url", "domain"],
    description="OpenPhish + PhishStats (keyless).",
    run=run,
))
