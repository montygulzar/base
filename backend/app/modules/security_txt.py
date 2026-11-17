"""security.txt parser (RFC 9116).

Fetches /.well-known/security.txt or /security.txt, parses Contact /
Encryption / Policy / Acknowledgments / Hiring fields. Emails and URLs
become entities.
"""
from __future__ import annotations
import re
import httpx
from urllib.parse import urlparse, urljoin
from ..utils.validators import is_domain, normalise_domain, is_email
from ..utils.ssrf import assert_public, SSRFBlocked
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def _try(c: httpx.AsyncClient, url: str) -> httpx.Response | None:
    try:
        r = await c.get(url, timeout=12)
        return r if r.status_code == 200 else None
    except Exception:
        return None


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("security_txt", "ssrf_blocked",
                                    {"url": url, "reason": str(e)}, 0.0))
        return out
    host = urlparse(url).hostname or ""
    if not host:
        return out
    out.entities.append(Entity("domain", host, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}, follow_redirects=True) as c:
        for path in ("/.well-known/security.txt", "/security.txt"):
            r = await _try(c, urljoin(url, path))
            if r:
                text = r.text
                fields: dict[str, list[str]] = {}
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        k, val = line.split(":", 1)
                        fields.setdefault(k.strip().lower(), []).append(val.strip())
                out.findings.append(Finding("security_txt", "record",
                                            {"url": str(r.url), "fields": fields,
                                             "raw_bytes": len(text)}, 0.95))
                for contact in fields.get("contact", []):
                    m = re.match(r"mailto:(.+)$", contact)
                    if m and is_email(m.group(1)):
                        em = m.group(1).lower()
                        out.entities.append(Entity("email", em, {"source": "security_txt"}, 0.9))
                        out.relationships.append(Relationship("domain", host, "email", em,
                                                              "security_contact", "security_txt", 0.95))
                    elif contact.startswith("http"):
                        out.entities.append(Entity("url", contact, {"source": "security_txt"}, 0.8))
                        out.relationships.append(Relationship("domain", host, "url", contact,
                                                              "security_contact", "security_txt", 0.95))
                for policy in fields.get("policy", []) + fields.get("acknowledgments", []):
                    if policy.startswith("http"):
                        out.entities.append(Entity("url", policy, {"source": "security_txt"}, 0.8))
                return out
    out.findings.append(Finding("security_txt", "not_found", {}, 0.3))
    return out


register(Module(
    key="security_txt",
    name="security.txt",
    subject_types=["domain", "url"],
    description="RFC 9116 security.txt parser (contacts, policies).",
    run=run,
))
