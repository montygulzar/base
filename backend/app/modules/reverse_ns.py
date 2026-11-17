"""Reverse NS — find other domains sharing the same nameservers.

Uses viewdns.info's free-tier HTML page as a last-resort scraping source.
Falls back to source_unavailable if scraping fails; no key required.
"""
from __future__ import annotations
import re
import httpx
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


DOMAIN_RE = re.compile(r"<td[^>]*>([a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})</td>")


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("reverse_ns", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "Mozilla/5.0 base-osint/0.1"}) as c:
        try:
            r = await c.get("https://viewdns.info/reversens/",
                            params={"ns": d}, timeout=20)
            if r.status_code == 200 and "<table" in r.text:
                hits = sorted(set(DOMAIN_RE.findall(r.text)))
                hits = [h for h in hits if h != d]
                out.findings.append(Finding("viewdns_reverse_ns", "share",
                                            {"ns": d, "domains": hits[:200],
                                             "count": len(hits)},
                                            0.75 if hits else 0.3))
                for h in hits[:200]:
                    out.entities.append(Entity("domain", h.lower(), {"shares_ns_with": d}, 0.7))
                    out.relationships.append(Relationship("domain", h.lower(), "domain", d,
                                                          "shares_ns_with", "viewdns.info", 0.65))
            else:
                out.findings.append(Finding("viewdns_reverse_ns", "source_unavailable",
                                            {"status": r.status_code,
                                             "reason": "viewdns scrape failed"}, 0.0))
        except Exception as e:
            out.findings.append(Finding("viewdns_reverse_ns", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="reverse_ns",
    name="Reverse NS",
    subject_types=["domain"],
    description="Find other domains hosted on the same nameserver.",
    run=run,
))
