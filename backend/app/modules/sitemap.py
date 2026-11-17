"""Sitemap crawler — parse /sitemap.xml and /sitemap_index.xml,
following nested indexes up to a bounded depth. Emits every <loc> as
a url entity.
"""
from __future__ import annotations
import re
import httpx
from urllib.parse import urljoin
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register

LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


async def _fetch(c: httpx.AsyncClient, url: str) -> str:
    try:
        r = await c.get(url, timeout=12, follow_redirects=True)
        if r.status_code == 200 and r.text.strip():
            return r.text
    except Exception:
        return ""
    return ""


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    base = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(base)
    except SSRFBlocked as e:
        out.findings.append(Finding("sitemap", "ssrf_blocked",
                                    {"url": base, "reason": str(e)}, 0.0))
        return out
    out.entities.append(Entity("url", base, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        all_urls: set[str] = set()
        candidates = [urljoin(base + "/", "sitemap.xml"),
                      urljoin(base + "/", "sitemap_index.xml"),
                      urljoin(base + "/", "sitemap1.xml")]
        for depth in range(3):
            if not candidates:
                break
            next_round: list[str] = []
            for u in candidates[:50]:
                body = await _fetch(c, u)
                if not body:
                    continue
                found = LOC_RE.findall(body)
                for loc in found:
                    if loc.endswith(".xml"):
                        next_round.append(loc)
                    else:
                        all_urls.add(loc)
            candidates = next_round
        out.findings.append(Finding("sitemap", "crawl",
                                    {"base": base, "unique_urls": len(all_urls),
                                     "sample": sorted(all_urls)[:100]},
                                    0.9 if all_urls else 0.3))
        for u in sorted(all_urls)[:200]:
            out.entities.append(Entity("url", u, {"from": "sitemap"}, 0.75))
            out.relationships.append(Relationship("url", base, "url", u,
                                                  "indexes", "sitemap.xml", 0.85))
    return out


register(Module(
    key="sitemap",
    name="Sitemap crawler",
    subject_types=["url", "domain"],
    description="Parses sitemap.xml (and nested indexes) for surface URLs.",
    run=run,
))
