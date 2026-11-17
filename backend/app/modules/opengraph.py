"""OpenGraph / Twitter card / schema.org / link-rel metadata extractor."""
from __future__ import annotations
import re
import httpx
from urllib.parse import urlparse, urljoin
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


META_RE = re.compile(r'<meta[^>]+>', re.I)
ATTR_RE = re.compile(r'([a-zA-Z0-9:_\-]+)\s*=\s*"([^"]*)"')
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
LINK_RE = re.compile(r'<link[^>]+rel=["\']([^"\']+)["\'][^>]+href=["\']([^"\']+)["\']', re.I)


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("opengraph", "ssrf_blocked",
                                    {"url": url, "reason": str(e)}, 0.0))
        return out
    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1"},
                                 follow_redirects=True) as c:
        try:
            r = await c.get(url, timeout=15)
        except Exception as e:
            out.findings.append(Finding("opengraph", "error", {"error": str(e)}, 0.1))
            return out
    if r.status_code != 200:
        out.findings.append(Finding("opengraph", "http_error", {"status": r.status_code}, 0.1))
        return out
    body = r.text[:500_000]
    metas: dict[str, str] = {}
    for m in META_RE.findall(body):
        attrs = dict(ATTR_RE.findall(m))
        name = attrs.get("name") or attrs.get("property") or attrs.get("itemprop")
        content = attrs.get("content")
        if name and content and name not in metas:
            metas[name.lower()] = content
    title = ""
    tm = TITLE_RE.search(body)
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1)).strip()
    links = [{"rel": rel, "href": urljoin(url, href)} for rel, href in LINK_RE.findall(body)]
    out.findings.append(Finding("opengraph", "metadata", {
        "url": str(r.url), "title": title, "meta_count": len(metas),
        "meta": metas, "links": links[:50],
    }, 0.9))
    return out


register(Module(
    key="opengraph",
    name="OpenGraph / metadata",
    subject_types=["url", "domain"],
    description="Meta tags, OpenGraph / Twitter cards / schema.org, link rels.",
    run=run,
))
