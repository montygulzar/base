"""TLD-variation squatting. bank.com → bank.net/org/co/io/… — check which
variants resolve.
"""
from __future__ import annotations
import asyncio
import dns.asyncresolver
import tldextract
from ..utils.validators import is_domain, normalise_domain
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.lifetime = 4.0

TLDS = ["com", "net", "org", "co", "io", "me", "info", "biz", "us",
        "ca", "uk", "de", "fr", "nl", "ru", "cn", "jp", "au", "in",
        "dev", "app", "xyz", "online", "site", "store", "shop",
        "cloud", "tech", "zone", "live", "life", "icu", "top"]


async def _a(host: str) -> list[str]:
    try:
        a = await RESOLVER.resolve(host, "A")
        return [r.to_text() for r in a]
    except Exception:
        return []


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    d = normalise_domain(subject)
    if not is_domain(d):
        out.findings.append(Finding("tld_twist", "invalid_input", {"input": subject}, 0.1))
        return out
    ex = tldextract.extract(d)
    base = ex.domain
    if not base:
        out.findings.append(Finding("tld_twist", "invalid_input", {"input": subject}, 0.1))
        return out
    candidates = sorted({f"{base}.{tld}" for tld in TLDS if f"{base}.{tld}" != d})
    sem = asyncio.Semaphore(32)
    async def chk(h):
        async with sem:
            return h, await _a(h)
    results = await asyncio.gather(*[chk(h) for h in candidates])
    live = [{"host": h, "ips": ips} for h, ips in results if ips]
    out.findings.append(Finding("tld_twist", "live",
                                {"base": base, "checked": len(candidates),
                                 "live": live},
                                0.9 if live else 0.3))
    for item in live[:60]:
        out.entities.append(Entity("domain", item["host"],
                                   {"tld_twist_of": d, "ips": item["ips"]}, 0.75))
        out.relationships.append(Relationship("domain", item["host"], "domain", d,
                                              "tld_twist_of", "tld_twist", 0.7,
                                              {"ips": item["ips"]}))
    return out


register(Module(
    key="tld_twist",
    name="TLD twist",
    subject_types=["domain"],
    description="Check same-root domain across 30+ TLDs.",
    run=run,
))
