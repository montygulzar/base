"""Web intelligence — probe, headers, robots/sitemap, tech, link extraction."""
from __future__ import annotations
from urllib.parse import urlparse, urljoin
import httpx
from ..utils.validators import is_domain, normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register

TECH_SIGNS = {
    "wordpress": ["wp-content", "wp-includes"],
    "drupal": ["/sites/default/files/", "Drupal.settings"],
    "cloudflare": ["cloudflare"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "react": ["__NEXT_DATA__", "react"],
    "vue": ["Vue.config"],
    "shopify": ["cdn.shopify.com"],
    "wix": ["_wixCIDX"],
}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if v.startswith("http") else "https://" + normalise_domain(v)
    host = urlparse(url).hostname or ""
    if not host:
        out.findings.append(Finding("web", "invalid_input", {"input": subject}, 0.1))
        return out
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("web", "ssrf_blocked", {"url": url, "reason": str(e)}, 0.0))
        return out
    out.entities.append(Entity("url", url, {}, 0.9))
    if is_domain(host):
        out.entities.append(Entity("domain", host, {}, 0.9))
        out.relationships.append(Relationship("url", url, "domain", host, "hosted_on", "url_parse", 0.95))

    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1"}, follow_redirects=True) as c:
        try:
            r = await c.get(url, timeout=s.HTTP_TIMEOUT_SECONDS)
            body = r.text
            out.findings.append(Finding("web", "page", {
                "status": r.status_code, "final_url": str(r.url),
                "bytes": len(body), "headers": dict(r.headers),
                "security_headers": {
                    "hsts": r.headers.get("strict-transport-security"),
                    "csp": r.headers.get("content-security-policy"),
                    "x-frame-options": r.headers.get("x-frame-options"),
                    "x-content-type-options": r.headers.get("x-content-type-options"),
                    "referrer-policy": r.headers.get("referrer-policy"),
                },
            }, 0.9))

            tech = []
            lower = body.lower()
            for name, needles in TECH_SIGNS.items():
                if any(n.lower() in lower for n in needles) or any(n.lower() in (r.headers.get("server","") or "").lower() for n in needles):
                    tech.append(name)
            out.findings.append(Finding("web", "tech_fingerprint", {"stack": tech}, 0.75 if tech else 0.2))

            from bs4 import BeautifulSoup  # lazy
            soup = BeautifulSoup(body, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else ""
            metas = {m.get("name") or m.get("property"): m.get("content") for m in soup.find_all("meta") if m.get("content")}
            links = sorted({urljoin(url, a.get("href")) for a in soup.find_all("a", href=True)})
            out.findings.append(Finding("web", "page_structure",
                                        {"title": title, "meta": metas, "link_count": len(links),
                                         "links_sample": links[:200]}, 0.85))
            for ln in links[:200]:
                host2 = urlparse(ln).hostname
                if host2 and host2 != host and is_domain(host2):
                    out.entities.append(Entity("domain", host2, {"from": "page_link"}, 0.6))
                    out.relationships.append(Relationship("url", url, "domain", host2, "links_to", "html_parse", 0.6))
        except Exception as e:
            out.findings.append(Finding("web", "error", {"error": str(e)}, 0.1))

        for path, kind in [("/robots.txt", "robots"), ("/sitemap.xml", "sitemap"), ("/.well-known/security.txt", "security_txt")]:
            try:
                r = await c.get(f"https://{host}{path}", timeout=10)
                if r.status_code == 200 and r.text.strip():
                    out.findings.append(Finding("web", kind, {"bytes": len(r.text), "preview": r.text[:3000]}, 0.85))
            except Exception:
                pass

    return out


register(Module(
    key="web",
    name="Web intelligence",
    subject_types=["url", "domain"],
    description="HTTP probe, headers, tech fingerprint, links, robots/sitemap.",
    run=run,
))
