"""Shodan DNS resolver — free, no-key `dns/domain/{domain}` endpoint.
Returns subdomains (as an index), DNS A records, and tags.
"""
from __future__ import annotations
import httpx
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("shodan_dns", "invalid_input", {"input": subject}, 0.1))
        return out
    out.entities.append(Entity("domain", d, {}, 0.9))
    async with httpx.AsyncClient(headers={"user-agent": "base-osint/0.1"}) as c:
        try:
            r = await c.get(f"https://internetdb.shodan.io/-/dns/{d}", timeout=15)
            # If that free endpoint is not available, fall through below.
            if r.status_code != 200:
                r = await c.get(f"https://api.shodan.io/dns/domain/{d}", timeout=15)
            if r.status_code == 200:
                j = r.json()
                out.findings.append(Finding("shodan_dns", "domain", j, 0.85))
                for row in (j.get("data") or [])[:500]:
                    sub = row.get("subdomain")
                    val = row.get("value")
                    full = f"{sub}.{d}" if sub else d
                    if is_domain(full):
                        out.entities.append(Entity("domain", full, {"shodan": True}, 0.75))
                        if sub:
                            out.relationships.append(Relationship("domain", full, "domain", d,
                                                                  "subdomain_of", "shodan_dns", 0.8))
            else:
                out.findings.append(Finding("shodan_dns", "http_error",
                                            {"status": r.status_code}, 0.1))
        except Exception as e:
            out.findings.append(Finding("shodan_dns", "error", {"error": str(e)}, 0.1))
    return out


register(Module(
    key="shodan_dns",
    name="Shodan DNS",
    subject_types=["domain"],
    description="Shodan DNS index (subdomains + A records).",
    run=run,
))
