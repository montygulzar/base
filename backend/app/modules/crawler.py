"""Photon-style crawler.

Bounded BFS from a seed URL, same-origin only. Extracts links, forms,
query parameters, email addresses, and script sources. Caps pages crawled
and total bytes to stay well-behaved; respects robots.txt if present.
"""
from __future__ import annotations
import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs
import httpx
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


UA = {"user-agent": "Mozilla/5.0 base-osint/0.1"}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
HREF_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)
FORM_RE = re.compile(r"<form[^>]*action=[\"']([^\"']+)[\"'][^>]*(?:method=[\"']([^\"']+)[\"'])?", re.I)


async def _robots(c: httpx.AsyncClient, base: str) -> set[str]:
    disallow: set[str] = set()
    try:
        r = await c.get(urljoin(base, "/robots.txt"), timeout=10)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallow.add(path)
    except Exception:
        pass
    return disallow


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip()
    seed = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(seed)
    except SSRFBlocked as e:
        out.findings.append(Finding("crawler", "ssrf_blocked", {"url": seed, "reason": str(e)}, 0.0))
        return out
    origin = urlparse(seed).netloc

    MAX_PAGES = 40
    MAX_BYTES = 8 * 1024 * 1024
    MAX_DEPTH = 2

    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(seed, 0)])
    pages: list[dict] = []
    emails: set[str] = set()
    scripts: set[str] = set()
    forms: list[dict] = []
    params: dict[str, set[str]] = {}
    external_hosts: set[str] = set()
    total_bytes = 0

    async with httpx.AsyncClient(headers=UA, follow_redirects=True) as c:
        disallow = await _robots(c, seed)
        while queue and len(visited) < MAX_PAGES and total_bytes < MAX_BYTES:
            url, depth = queue.popleft()
            if url in visited or any(url.startswith(urljoin(seed, p)) for p in disallow):
                continue
            visited.add(url)
            try:
                r = await c.get(url, timeout=12)
                total_bytes += len(r.content or b"")
                if r.status_code >= 400 or "text/html" not in (r.headers.get("content-type") or ""):
                    pages.append({"url": url, "status": r.status_code, "skipped": True})
                    continue
                body = r.text
                pages.append({"url": url, "status": r.status_code, "bytes": len(body)})

                for m in EMAIL_RE.findall(body):
                    emails.add(m.lower())
                for m in SCRIPT_SRC_RE.findall(body):
                    scripts.add(urljoin(url, m))
                for action, method in FORM_RE.findall(body):
                    forms.append({"on": url, "action": urljoin(url, action), "method": (method or "GET").upper()})

                for href in HREF_RE.findall(body):
                    if href.startswith(("mailto:", "javascript:", "#")):
                        continue
                    abs_url = urljoin(url, href)
                    p = urlparse(abs_url)
                    if p.netloc and p.netloc != origin:
                        external_hosts.add(p.netloc)
                        continue
                    for k, vs in parse_qs(p.query).items():
                        params.setdefault(k, set()).update(vs)
                    if abs_url not in visited and depth < MAX_DEPTH:
                        queue.append((abs_url, depth + 1))
            except Exception as e:
                pages.append({"url": url, "error": str(e)})

    out.findings.append(Finding("crawler", "summary", {
        "seed": seed, "pages_visited": len(pages),
        "unique_emails": len(emails), "scripts": len(scripts),
        "forms": len(forms), "query_params": len(params),
        "external_hosts": len(external_hosts),
        "bytes": total_bytes,
    }, 0.9))
    out.findings.append(Finding("crawler", "pages", {"pages": pages[:200]}, 0.85))
    out.findings.append(Finding("crawler", "emails", {"emails": sorted(emails)}, 0.85))
    out.findings.append(Finding("crawler", "scripts", {"scripts": sorted(scripts)[:200]}, 0.85))
    out.findings.append(Finding("crawler", "forms", {"forms": forms[:200]}, 0.85))
    out.findings.append(Finding("crawler", "params", {"params": {k: sorted(v)[:20] for k, v in params.items()}}, 0.8))
    out.findings.append(Finding("crawler", "external_hosts",
                                {"hosts": sorted(external_hosts)}, 0.8))

    for em in emails:
        out.entities.append(Entity("email", em, {"from": "crawler"}, 0.7))
        out.relationships.append(Relationship("url", seed, "email", em, "mentions", "crawler", 0.75))
    for host in external_hosts:
        out.entities.append(Entity("domain", host.lower(), {"from": "crawler"}, 0.65))
        out.relationships.append(Relationship("url", seed, "domain", host.lower(), "links_to", "crawler", 0.65))

    return out


register(Module(
    key="crawler",
    name="Site crawler (Photon-style)",
    subject_types=["url", "domain"],
    description="Bounded BFS, same-origin. Extracts emails, scripts, forms, params, external hosts.",
    run=run,
))
